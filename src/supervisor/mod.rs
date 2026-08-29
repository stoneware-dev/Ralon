//! Binding `agent.lock` to enforcement, without anyone running a command.
//!
//! The supervisor invents no new way to stop a write. It runs the *lifecycle* of
//! the mechanism the platform already has: notice a policy file, start the
//! enforcement `ralon guard` would have started, and take it down again when the
//! policy goes away. That is deliberate, and it is what keeps the boundary
//! honest — nothing here is easier to bypass than `ralon guard` is, because it
//! *is* `ralon guard`, started by something other than a person.
//!
//! Which means the supervisor exists exactly where a guard can: on platforms
//! whose enforcement is *held* by a process and refused to everyone else. Where
//! enforcement is *inherited* — Linux — there is nothing for a background
//! process to hold, and `ralon install` says so rather than registering a daemon
//! with no work to do.
//!
//! ## Shape
//!
//! [`reconcile`] is pure: remembered state plus what is on disk gives a list of
//! actions. It has no idea what platform it is on, which is the same split the
//! rest of the codebase uses — planning everywhere, syscalls behind one door —
//! and it means the state machine is tested on every machine including the ones
//! that cannot enforce anything.
//!
//! Everything impure is in [`Supervisor::tick`], and all of it goes through
//! `enforce::guard`, whose interface already says "hold this policy open with no
//! command to supervise". The supervisor adds no platform code of its own.

pub mod registry;
pub mod selfguard;
pub mod single;
pub mod volumes;
pub mod watch;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::enforce::{self, Backend, Plan};
use crate::matcher::Matcher;
use crate::policy::{Policy, POLICY_FILE};
use crate::scan;
use registry::{Registry, State, Workspace};

/// How often the sweep runs when the watcher has said nothing.
///
/// The watcher is the mechanism; this is the backstop behind it. A missed
/// notification — a watcher that failed to start, a directory moved wholesale,
/// an event coalesced away under load — becomes a minute of delay instead of a
/// workspace that is never noticed.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// What has to change about one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Turn the policy into enforcement.
    Begin(PathBuf),
    /// Release enforcement and undo whatever was applied.
    End(PathBuf),
    /// Nothing is applied and there is no policy — stop remembering it.
    Forget(PathBuf),
}

/// What has to happen, from three facts about each workspace.
///
/// - `known` — what the supervisor last recorded.
/// - `on_disk` — where an `agent.lock` is right now.
/// - `live` — where enforcement is *actually* in place right now, asked of the
///   kernel rather than of the notes.
///
/// The third is not redundant with the first, and leaving it out was a bug worth
/// naming. On Windows enforcement lives in a process, so a reboot ends all of it
/// while `workspaces.json` still says `enforced` — a supervisor that trusted its
/// own notes would come up after a restart, agree with itself that everything
/// was fine, and protect nothing. The same gap covers a guard that was killed.
/// So the record says what was *intended*, the kernel says what is *true*, and
/// where they disagree the kernel wins.
///
/// (On macOS the two rarely disagree: the flag is on the inode and survives
/// reboots, so `live` is still true afterwards and nothing needs redoing. Same
/// code, different answer, which is the point of asking rather than assuming.)
///
/// `retry_failed` is false for the many small passes a watcher triggers and true
/// for the periodic sweep. A policy that does not parse would otherwise be
/// re-read on every event that touches the directory, and would log the same
/// complaint each time; once a minute is enough to notice it was fixed.
pub fn reconcile(
    known: &[Workspace],
    on_disk: &BTreeSet<PathBuf>,
    live: &BTreeSet<PathBuf>,
    now: u64,
    retry_failed: bool,
) -> Vec<Action> {
    let mut actions = Vec::new();

    for root in on_disk {
        match known.iter().find(|entry| &entry.root == root) {
            None => actions.push(Action::Begin(root.clone())),
            Some(entry) => match &entry.state {
                // Believed to be enforced. Only left alone if it really is.
                State::Enforced => {
                    if !live.contains(root) {
                        actions.push(Action::Begin(root.clone()));
                    }
                }
                // A pause that has run out is over. Nobody has to remember to
                // end it, which is the point of it having an end.
                State::Paused { until: Some(until) } if *until <= now => {
                    actions.push(Action::Begin(root.clone()))
                }
                // Still paused. If enforcement is somehow still in place — a
                // pause written by hand, a release that failed halfway — take it
                // off, so the record and the machine agree.
                State::Paused { .. } => {
                    if live.contains(root) || !entry.applied.is_empty() {
                        actions.push(Action::End(root.clone()));
                    }
                }
                State::Failed { .. } => {
                    if retry_failed {
                        actions.push(Action::Begin(root.clone()));
                    }
                }
            },
        }
    }

    for entry in known {
        if on_disk.contains(&entry.root) {
            continue;
        }
        // The policy is gone. Anything applied under it has to come off, and
        // this is the only place that can: the paths cannot be recomputed from a
        // file that no longer exists, which is why they were remembered.
        if live.contains(&entry.root) || !entry.applied.is_empty() {
            actions.push(Action::End(entry.root.clone()));
        } else {
            actions.push(Action::Forget(entry.root.clone()));
        }
    }

    actions
}

/// The running daemon.
pub struct Supervisor {
    registry: Registry,
    log: Option<std::fs::File>,
    /// Printed as well as logged. False for the detached daemon, which has no
    /// console to print to.
    pub verbose: bool,
}

impl Supervisor {
    pub fn load() -> Result<Supervisor> {
        let registry = Registry::load()?;
        Ok(Supervisor {
            log: open_log(&registry),
            registry,
            verbose: false,
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// One pass: look, decide, act, remember.
    ///
    /// Returns what it did, which is what the tests assert on and what `--once`
    /// prints. The registry is reloaded first so that `ralon pause` in another
    /// terminal is seen, rather than being overwritten by whatever this process
    /// last held in memory.
    pub fn tick(&mut self, retry_failed: bool) -> Result<Vec<Action>> {
        self.registry = Registry::load()?;

        let on_disk = registry::sweep(&self.registry.config);
        // Asked of every root in either list, because the two disagree exactly
        // when it matters: a workspace whose policy is gone may still be held,
        // and a workspace whose policy is there may no longer be.
        let live: BTreeSet<PathBuf> = on_disk
            .iter()
            .chain(self.registry.workspaces.iter().map(|entry| &entry.root))
            .filter(|root| enforce::guard::running(root))
            .cloned()
            .collect();

        let actions = reconcile(
            &self.registry.workspaces,
            &on_disk,
            &live,
            registry::now(),
            retry_failed,
        );

        for action in &actions {
            match action {
                Action::Begin(root) => self.begin(root),
                Action::End(root) => self.end(root),
                Action::Forget(root) => self.registry.forget(root),
            }
        }

        if !actions.is_empty() {
            self.registry.save_workspaces()?;
        }
        Ok(actions)
    }

    /// Reconciles only the workspaces a watcher pointed at.
    ///
    /// A notification names a directory, not a project, so the enclosing project
    /// is what gets looked at — and only if it sits inside a registered scan
    /// root, so an event about a path nobody registered cannot introduce a
    /// workspace the configuration does not allow.
    pub fn tick_for(&mut self, changed: &[PathBuf]) -> Result<Vec<Action>> {
        if changed.iter().any(|path| self.registry.config.covers(path)) {
            return self.tick(false);
        }
        Ok(Vec::new())
    }

    /// Adds scopes without disturbing the ones already declared.
    ///
    /// Additive on purpose — see the note at the call site in `install`. Returns
    /// what each one did, so the caller can report "absorbed three narrower
    /// scopes" rather than leaving the developer to compare `scope list` before
    /// and after.
    pub fn add_scopes(
        &mut self,
        roots: &[PathBuf],
        depth: Option<usize>,
        hooks: bool,
    ) -> Result<Vec<registry::ScopeChange>> {
        let changes = roots
            .iter()
            .map(|root| self.registry.config.add(root.clone()))
            .collect();
        self.registry.config.hooks = hooks;
        if let Some(depth) = depth {
            self.registry.config.max_depth = depth;
        }
        self.registry.save_config()?;
        Ok(changes)
    }

    pub fn add_scope(&mut self, root: PathBuf) -> registry::ScopeChange {
        self.registry.config.add(root)
    }

    pub fn remove_scope(&mut self, root: &Path) -> bool {
        self.registry.config.remove(root)
    }

    pub fn save_config(&self) -> Result<()> {
        self.registry.save_config()
    }

    /// Releases one project and records that it was deliberate.
    ///
    /// Done here rather than left to the next tick so that when the command
    /// returns, the policy file really is writable — otherwise `ralon pause &&
    /// $EDITOR agent.lock` races the supervisor and loses about half the time.
    pub fn pause(&mut self, root: &Path, until: Option<u64>) -> Result<()> {
        self.end(root);
        self.registry.set(root, State::Paused { until }, Vec::new());
        self.registry.save_workspaces()
    }

    /// Takes it back, now, for the same reason.
    pub fn resume(&mut self, root: &Path) -> Result<()> {
        self.registry.forget(root);
        self.begin(root);
        self.registry.save_workspaces()
    }

    /// Hands back everything this supervisor is holding.
    ///
    /// Returns the roots it released. Driven by the registry rather than by a
    /// sweep of the disk, so a project whose `agent.lock` has already been
    /// deleted is still cleaned up — which is the case that would otherwise
    /// leave a machine with immutable files and nothing left that knows why.
    pub fn release_all(&mut self) -> Result<Vec<PathBuf>> {
        let roots: Vec<PathBuf> = self
            .registry
            .workspaces
            .iter()
            .map(|entry| entry.root.clone())
            .collect();
        for root in &roots {
            self.end(root);
            self.registry.forget(root);
        }
        self.registry.save_workspaces()?;
        Ok(roots)
    }

    fn begin(&mut self, root: &Path) {
        let applied = match self.plan_for(root) {
            Ok(applied) => applied,
            Err(error) => {
                let reason = format!("{error:#}");
                self.say(&format!(
                    "cannot enforce {}: {reason}",
                    registry::display(root)
                ));
                self.registry
                    .set(root, State::Failed { reason }, Vec::new());
                return;
            }
        };

        // Before the guard, not after. Once enforcement is in place the project
        // is locked, and a policy that happens to protect the agent's own
        // configuration directory would make this impossible — which would be a
        // strange way to lose the one message Ralon actually owns.
        self.configure_agents(root);

        // Already claimed — by a guard the developer started by hand, or by one
        // this supervisor started before it was restarted. Either way the
        // project is protected and starting a second would fail, so being
        // already-done is success. This is where idempotence actually lives:
        // the claim is a kernel object, so it is true across processes and
        // across restarts without anything being written down.
        if enforce::guard::running(root) {
            self.registry.set(root, State::Enforced, applied);
            return;
        }

        match enforce::guard::detach(root) {
            Ok(()) => {
                self.say(&format!(
                    "enforcing {} ({} paths)",
                    registry::display(root),
                    applied.len()
                ));
                self.note_weaknesses(root);
                self.registry.set(root, State::Enforced, applied);
            }
            Err(error) => {
                // Asked again rather than believed. `detach` reports an error
                // when it gives up waiting for the claim, which is not the same
                // as the claim never being taken — and recording "failed" for a
                // project that is in fact protected is the one direction of
                // wrongness that makes `ralon status` lie. The kernel object is
                // the fact; everything else is a report about it.
                if enforce::guard::running(root) {
                    self.registry.set(root, State::Enforced, applied);
                    return;
                }
                let reason = format!("{error:#}");
                self.say(&format!("cannot enforce {}: {reason}", root.display()));
                self.registry
                    .set(root, State::Failed { reason }, Vec::new());
            }
        }
    }

    fn end(&mut self, root: &Path) {
        let applied = self
            .registry
            .find(root)
            .map(|entry| entry.applied.clone())
            .unwrap_or_default();

        if let Err(error) = enforce::guard::stop(root) {
            self.say(&format!(
                "could not release {}: {error:#}",
                registry::display(root)
            ));
        }
        // Whether or not a guard was running: a supervisor that was killed
        // leaves the applied state behind, and this is where it is cleared.
        // Driven by the remembered paths, because by now the policy that named
        // them may be gone.
        let cleared = enforce::guard::clear_leftovers(&applied);
        self.say(&format!(
            "released {} ({} cleared)",
            registry::display(root),
            cleared.len()
        ));

        // Still a workspace if the policy is still there — it is paused, not
        // gone — so the state is only dropped when there is nothing left.
        match self.registry.find(root).map(|entry| entry.state.clone()) {
            Some(State::Paused { until }) => {
                self.registry.set(root, State::Paused { until }, Vec::new())
            }
            _ => self.registry.forget(root),
        }
    }

    /// Writes the agent hook into a project that is about to be enforced.
    ///
    /// This is what decides whether an agent hitting a protected path reads
    /// "protected by Ralon" or `EBUSY: resource busy or locked`. Both mean the
    /// same thing to the filesystem and nothing like the same thing to the agent:
    /// the second one reads as a corrupt file, so it retries, renames around it,
    /// and shells out — none of which work, all of which waste a few minutes and
    /// end with the developer being told their repository is broken.
    ///
    /// Ralon cannot rewrite the OS error; it is produced inside the agent's own
    /// runtime from a code Ralon caused but does not own. The hook is the only
    /// interception point that exists, which is why it is installed by default
    /// rather than being left as something to discover afterwards.
    ///
    /// Never fatal. Enforcement does not depend on it, and a project whose hook
    /// could not be written is still protected — just less politely.
    fn configure_agents(&mut self, root: &Path) {
        if !self.registry.config.hooks {
            return;
        }
        match crate::hook::install_for(root, crate::cli::Agent::Auto, false) {
            Ok(installed) => {
                let written = installed.iter().filter(|entry| !entry.replaced).count();
                if written > 0 {
                    self.say(&format!(
                        "configured {written} agents in {}",
                        registry::display(root)
                    ));
                }
            }
            Err(error) => self.say(&format!(
                "could not configure the agents in {}: {error:#} — the policy is \
                 still enforced, but an agent will see the raw filesystem error \
                 rather than being told why",
                registry::display(root)
            )),
        }
    }

    /// What enforcement would cover, resolved against the disk.
    ///
    /// Run before anything is started so a policy that does not parse is a
    /// workspace that reports why, rather than a guard that fails to launch with
    /// its reason going to a console nobody is attached to.
    fn plan_for(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let policy = Policy::load(root)?;
        let matcher = Matcher::new(&policy.patterns)?;
        let found = scan::scan(&policy.root, &matcher)?;
        let protected = scan::canonical_targets(&found)?;
        let canonical = std::fs::canonicalize(&policy.root)?;
        // Built for its side effect of being buildable: if the policy cannot
        // become a plan, that is worth finding out here.
        let _ = Plan::build(Backend::Auto, &canonical, protected.clone());
        Ok(protected)
    }

    /// Records what enforcement is about to *not* cover.
    ///
    /// A hard link to a protected file, or a project reachable at a second mount
    /// point, is a hole no backend closes — the locks are taken on the path the
    /// policy names, and another name for the same bytes is another path. `check`
    /// and `status` have always said so, but those are commands a person runs;
    /// under the supervisor nobody runs anything, which is the entire point of
    /// it, so the one moment this could be said was going by in silence.
    ///
    /// It goes in the log rather than blocking enforcement. These are conditions
    /// to know about, not reasons to leave a project unprotected.
    fn note_weaknesses(&mut self, root: &Path) {
        let Ok(policy) = Policy::load(root) else {
            return;
        };
        let Ok(matcher) = Matcher::new(&policy.patterns) else {
            return;
        };
        let Ok(found) = scan::scan(&policy.root, &matcher) else {
            return;
        };

        for finding in crate::audit::audit(&policy.root, &found) {
            self.say(&format!(
                "warning: {} in {}: {}",
                finding.subject,
                registry::display(root),
                finding.detail
            ));
        }
        for finding in crate::audit::exposed_ancestors(&found) {
            self.say(&format!(
                "warning: {} in {}: {}",
                finding.subject,
                registry::display(root),
                finding.detail
            ));
        }
    }

    fn say(&mut self, message: &str) {
        if self.verbose {
            println!("ralon: {message}");
        }
        if let Some(log) = &mut self.log {
            let _ = writeln!(log, "{}  {message}", registry::timestamp(registry::now()));
            let _ = log.flush();
        }
    }
}

/// Runs until stopped.
///
/// The watcher is what makes this immediate; the sweep behind it is what makes
/// it correct when the watcher is not available or missed something. Both feed
/// the same `tick`, so there is one code path regardless of which noticed.
pub fn run(supervisor: &mut Supervisor) -> Result<()> {
    let _claim = single::claim().context("another Ralon supervisor is already running")?;

    // Canonical, so the "is it already inside a scope" test below compares like
    // with like. Scopes are canonical and `RALON_HOME` is whatever was typed —
    // on Windows that is `\\?\C:\...` against `C:\...`, which never matches, and
    // the state directory was registered a second time on top of the scope that
    // already contained it: two sets of handles and threads reporting the same
    // events.
    let state = supervisor.registry.home().to_path_buf();
    let state = std::fs::canonicalize(&state).unwrap_or(state);
    let mut watched = supervisor.registry.config.roots.clone();
    let mut watcher = watch::start(&registrations(&watched, &state));
    supervisor.say(&format!("supervisor started — {}", watcher.describe()));

    // Ralon's own binary and its record of the scopes, held for as long as this
    // process runs. Neither is a protected path, so nothing else here would ever
    // have mentioned them being changed.
    let mut holdings = selfguard::hold(supervisor.registry.home());
    for warning in std::mem::take(&mut holdings.warnings) {
        supervisor.say(&format!("warning: {warning}"));
    }

    // Said once here rather than per project, because it is a fact about the
    // machine and not about any workspace. Under the supervisor nobody runs
    // `status`, so without this the one condition that makes every installed
    // hook inert has nowhere to be reported at all — which is how it went
    // unnoticed long enough for an agent to be handed `EBUSY` and believe the
    // repository was broken.
    if supervisor.registry.config.hooks {
        let home = supervisor.registry.home().to_path_buf();
        if let Some(warning) = crate::hook::unreachable_warning(&home) {
            supervisor.say(&format!("warning: {warning}"));
        }
    }

    // Before waiting on anything: the state on disk may have moved on while no
    // supervisor was running, and after a reboot this pass is the whole job.
    supervisor.tick(true)?;
    let mut swept = Instant::now();

    loop {
        // The remaining slice of the sweep interval, not the whole of it. A
        // scope with any activity in it produces a steady trickle of
        // notifications, and waiting the full interval after each one would mean
        // the periodic sweep never runs on a machine that is being used — which
        // is the machine it exists for.
        let changed = watcher.changes(SWEEP_INTERVAL.saturating_sub(swept.elapsed()));

        // Two files decide what should be enforced, and everything else under a
        // scope is noise: a build, a `git checkout`, an editor writing a
        // temporary file. Filtering here rather than reconciling on every event
        // is what makes a scope on a home directory affordable — `AppData` alone
        // is written to continuously by software that has nothing to do with
        // this, and a full sweep per notification made the supervisor busy
        // whenever the developer was.
        let policy = changed.iter().any(|path| named(path, POLICY_FILE));
        let scopes = changed
            .iter()
            .any(|path| named(path, registry::CONFIG_FILE));

        if scopes || swept.elapsed() >= SWEEP_INTERVAL {
            supervisor.tick(true)?;
            swept = Instant::now();
        } else if policy {
            supervisor.tick_for(&changed)?;
        }

        // `ralon scope add D:\Projects` writes the configuration, and the state
        // directory is registered above precisely so that write arrives here.
        // Without it a supervisor would hold the registrations it started with
        // and every project on the new drive would wait for the sweep — which is
        // what happened, and only looked like it worked because the state
        // directory happened to sit under the one scope being watched.
        //
        // The replacement is built before the old one is dropped, so both exist
        // for an instant. That is fine — two read-only registrations on the same
        // directory do not conflict — and the old handles and threads go as soon
        // as the assignment completes.
        if supervisor.registry.config.roots != watched {
            watched = supervisor.registry.config.roots.clone();
            watcher = watch::start(&registrations(&watched, &state));
            supervisor.say(&format!("scopes changed — {}", watcher.describe()));
        }
    }
}

/// The scopes, plus the state directory so the supervisor hears about its own
/// configuration changing.
fn registrations(roots: &[PathBuf], state: &Path) -> Vec<PathBuf> {
    let mut all = roots.to_vec();
    if !all.iter().any(|root| state.starts_with(root)) {
        all.push(state.to_path_buf());
    }
    all
}

fn named(path: &Path, name: &str) -> bool {
    path.file_name().is_some_and(|actual| actual == name)
}

fn open_log(registry: &Registry) -> Option<std::fs::File> {
    let path = registry.log_path();
    let _ = std::fs::create_dir_all(registry.home());
    // A daemon that runs for months should not write an unbounded file, and
    // rotation would be a feature to maintain. Starting over once it is large
    // keeps the recent history, which is the part anyone reads.
    if std::fs::metadata(&path).map(|data| data.len()).unwrap_or(0) > 1_000_000 {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(root: &str, state: State, applied: &[&str]) -> Workspace {
        Workspace {
            root: PathBuf::from(root),
            state,
            applied: applied.iter().map(PathBuf::from).collect(),
        }
    }

    fn paths(roots: &[&str]) -> BTreeSet<PathBuf> {
        roots.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn a_new_policy_file_starts_enforcement() {
        let actions = reconcile(&[], &paths(&["/a"]), &paths(&[]), 0, false);
        assert_eq!(actions, [Action::Begin(PathBuf::from("/a"))]);
    }

    #[test]
    fn a_workspace_that_is_enforced_and_live_is_left_alone() {
        let known = [known("/a", State::Enforced, &["/a/.env"])];
        assert!(reconcile(&known, &paths(&["/a"]), &paths(&["/a"]), 0, true).is_empty());
    }

    #[test]
    fn enforcement_that_did_not_survive_a_reboot_is_started_again() {
        // The state Windows comes back in: the record says enforced, the
        // process that was enforcing it died with the machine. Believing the
        // record here is a supervisor that protects nothing and says it is fine.
        let known = [known("/a", State::Enforced, &["/a/.env"])];
        assert_eq!(
            reconcile(&known, &paths(&["/a"]), &paths(&[]), 0, false),
            [Action::Begin(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn a_guard_that_was_killed_is_started_again() {
        // Indistinguishable from the reboot case by design — "the record says
        // yes and the kernel says no" has one answer however it came about.
        let known = [
            known("/a", State::Enforced, &["/a/.env"]),
            known("/b", State::Enforced, &["/b/.env"]),
        ];
        assert_eq!(
            reconcile(&known, &paths(&["/a", "/b"]), &paths(&["/b"]), 0, false),
            [Action::Begin(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn a_removed_policy_file_releases_what_was_applied() {
        let known = [known("/a", State::Enforced, &["/a/.env"])];
        let actions = reconcile(&known, &paths(&[]), &paths(&["/a"]), 0, false);
        assert_eq!(actions, [Action::End(PathBuf::from("/a"))]);
    }

    #[test]
    fn a_policy_removed_while_the_supervisor_was_down_is_still_released() {
        // Nothing is live — the machine rebooted — but the flags or the ACL a
        // previous supervisor applied may still be on disk, and this is the
        // only record of where they are.
        let known = [known("/a", State::Enforced, &["/a/.env"])];
        assert_eq!(
            reconcile(&known, &paths(&[]), &paths(&[]), 0, false),
            [Action::End(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn a_removed_policy_with_nothing_applied_is_only_forgotten() {
        let known = [known(
            "/a",
            State::Failed {
                reason: "bad".into(),
            },
            &[],
        )];
        let actions = reconcile(&known, &paths(&[]), &paths(&[]), 0, false);
        assert_eq!(actions, [Action::Forget(PathBuf::from("/a"))]);
    }

    #[test]
    fn each_workspace_is_decided_on_its_own() {
        let known = [
            known("/a", State::Enforced, &["/a/.env"]),
            known(
                "/b",
                State::Failed {
                    reason: "bad".into(),
                },
                &[],
            ),
        ];
        // /a keeps running, /b is retried, /c is new. One broken policy does
        // not disturb the others, which is what "multiple repositories do not
        // interfere" has to mean at this layer.
        let actions = reconcile(
            &known,
            &paths(&["/a", "/b", "/c"]),
            &paths(&["/a"]),
            0,
            true,
        );
        assert_eq!(
            actions,
            [
                Action::Begin(PathBuf::from("/b")),
                Action::Begin(PathBuf::from("/c")),
            ]
        );
    }

    #[test]
    fn a_broken_policy_is_not_retried_on_every_event() {
        let known = [known(
            "/a",
            State::Failed {
                reason: "bad".into(),
            },
            &[],
        )];
        assert!(reconcile(&known, &paths(&["/a"]), &paths(&[]), 0, false).is_empty());
        assert_eq!(
            reconcile(&known, &paths(&["/a"]), &paths(&[]), 0, true),
            [Action::Begin(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn a_pause_holds_and_then_expires() {
        let known = [known("/a", State::Paused { until: Some(100) }, &[])];
        assert!(reconcile(&known, &paths(&["/a"]), &paths(&[]), 99, true).is_empty());
        assert_eq!(
            reconcile(&known, &paths(&["/a"]), &paths(&[]), 100, true),
            [Action::Begin(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn an_indefinite_pause_never_expires_on_its_own() {
        let known = [known("/a", State::Paused { until: None }, &[])];
        assert!(reconcile(&known, &paths(&["/a"]), &paths(&[]), u64::MAX, true).is_empty());
    }

    #[test]
    fn a_pause_that_is_still_being_enforced_is_released() {
        let known = [known("/a", State::Paused { until: None }, &[])];
        assert_eq!(
            reconcile(&known, &paths(&["/a"]), &paths(&["/a"]), 0, false),
            [Action::End(PathBuf::from("/a"))]
        );
    }
}
