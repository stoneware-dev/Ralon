//! `install once → create agent.lock → enforced`, tested against the real thing.
//!
//! These drive the actual binary against actual directories and then **read the
//! files back**. Not one assertion here trusts an exit code: `del` returns 0
//! when it failed and `>` returns 0 when it was refused, and two bugs in this
//! project's history were "attack refused" reported by a check that never opened
//! the file.
//!
//! Every test gets its own state directory and its own tree of repositories, so
//! they can run in parallel and so nothing here can disturb a supervisor the
//! developer has installed for real. For the same reason nothing in this file
//! runs `ralon install` or `ralon uninstall`: registering a logon task or a
//! LaunchAgent is machine-wide by nature, and a test suite that deregistered the
//! developer's own supervisor would be a worse bug than any it could catch. The
//! registration itself is unit-tested in `service/`, where the document it
//! produces can be inspected without installing it.

// Most of the harness below drives enforcement, and on Linux there is none —
// `install` refuses there, so those tests are compiled out and their helpers
// with them. Kept in one file rather than split, because the Linux tests assert
// on the *refusal*, and the two belong next to each other: whichever platform
// you are reading this on, the answer for the other one is on the same page.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ralon");

const POLICY: &str = "version: 1\nprotect:\n  - .env\n  - src/index.tsx\n  - config/**\n";

/// A machine with Ralon set up on it: a state directory and a place where the
/// developer keeps code.
struct Machine {
    home: PathBuf,
    code: PathBuf,
    projects: std::cell::RefCell<Vec<PathBuf>>,
}

impl Machine {
    fn new() -> Machine {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ralon-sup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        // Canonical from here down, because a scope Ralon reports is canonical
        // and a fixture holding the other spelling of the same directory
        // compares two strings that are equal on disk and different as text.
        // This machine's temporary directory is already canonical, so it passed
        // here and failed on both CI runners: `C:\Users\RUNNER~1\...` is an 8.3
        // short name, and macOS `/var` is a symlink to `/private/var`.
        // Reproduced by pointing `TMP` at a short name before fixing it.
        let root = plain(&fs::canonicalize(&root).unwrap());

        let home = root.join("state");
        let code = root.join("code");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&code).unwrap();

        let machine = Machine {
            home,
            code,
            projects: std::cell::RefCell::new(Vec::new()),
        };
        // What `ralon install` writes. Written directly so the test never has to
        // register anything with the operating system.
        machine.configure(std::slice::from_ref(&machine.code));
        machine
    }

    fn configure(&self, roots: &[PathBuf]) {
        self.write_config(roots, true);
    }

    /// Rewrites the config, keeping the scopes, with the hooks turned off.
    fn set_hooks(&self, hooks: bool) {
        self.write_config(std::slice::from_ref(&self.code), hooks);
    }

    fn write_config(&self, roots: &[PathBuf], hooks: bool) {
        let mut text = String::from("roots:\n");
        for root in roots {
            let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            text.push_str(&format!("- {}\n", yaml(&canonical)));
        }
        text.push_str("max_depth: 8\n");
        text.push_str(&format!("hooks: {hooks}\n"));
        fs::write(self.home.join("config.yaml"), text).unwrap();
    }

    /// A directory outside every configured scope.
    ///
    /// Stands in for `D:\Projects` on a machine whose only scope is a home
    /// directory on `C:` — the case that made the scope model a problem worth
    /// redesigning. A sibling of `code` rather than a child, so no scope reaches
    /// it until one is added on purpose.
    fn elsewhere(&self, name: &str) -> PathBuf {
        let root = self
            .home
            .parent()
            .expect("the state directory has a parent");
        let path = root.join(name);
        fs::create_dir_all(&path).unwrap();
        plain(&fs::canonicalize(&path).unwrap())
    }

    /// A repository, with or without a policy in it.
    fn repository(&self, name: &str, policy: Option<&str>) -> Repository {
        self.repository_in(&self.code.clone(), name, policy)
    }

    fn repository_in(&self, parent: &Path, name: &str, policy: Option<&str>) -> Repository {
        let root = parent.join(name);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(root.join(".env"), "SECRET=original").unwrap();
        fs::write(root.join("src/index.tsx"), "original").unwrap();
        fs::write(root.join("src/App.tsx"), "original").unwrap();
        fs::write(root.join("config/db.yaml"), "original").unwrap();

        // Canonicalized and then un-prefixed. `fs::canonicalize` on Windows
        // returns the verbatim form, `\\?\C:\...`, which is the right identity
        // for the supervisor and a path `cmd.exe` cannot open — and every attack
        // in this file goes through `cmd`, so a verbatim path here would make
        // the attacks fail for the wrong reason and the tests pass for it.
        let repository = Repository {
            root: plain(&fs::canonicalize(&root).unwrap()),
            home: self.home.clone(),
        };
        self.projects.borrow_mut().push(repository.root.clone());
        if let Some(policy) = policy {
            repository.declare(policy);
        }
        repository
    }

    fn ralon(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .args(arguments)
            .env("RALON_HOME", &self.home)
            .output()
            .expect("failed to run ralon")
    }

    /// One pass of the supervisor, as the daemon would do it.
    fn tick(&self) -> Output {
        self.ralon(&["daemon", "--once"])
    }

    fn recorded(&self) -> String {
        fs::read_to_string(self.home.join("workspaces.json")).unwrap_or_default()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Releasing before deleting, in that order and unconditionally. A guard
        // holds its files open, so a temp directory with one still running
        // cannot be removed on Windows — and the leftover process would hold the
        // test binary's own `ralon.exe` open too, which is how a suite starts
        // failing to rebuild for reasons nobody can see.
        for root in self.projects.borrow().iter() {
            let _ = Command::new(BINARY)
                .arg("--dir")
                .arg(root)
                .args(["guard", "--stop"])
                .env("RALON_HOME", &self.home)
                .output();
        }
        if let Some(parent) = self.home.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

struct Repository {
    root: PathBuf,
    home: PathBuf,
}

impl Repository {
    fn declare(&self, policy: &str) {
        fs::write(self.root.join("agent.lock"), policy).unwrap();
    }

    fn undeclare(&self) {
        fs::remove_file(self.root.join("agent.lock")).unwrap();
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.path(relative)).unwrap_or_default()
    }

    fn ralon(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(arguments)
            .env("RALON_HOME", &self.home)
            .current_dir(&self.root)
            .output()
            .expect("failed to run ralon")
    }

    /// Feeds one agent request to `ralon hook check`, the way an installed hook
    /// does. This is the only interception point whose wording Ralon owns, so
    /// what comes back is worth asserting on directly.
    fn hook(&self, request: &str) -> Output {
        use std::io::Write;

        let mut child = Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(["hook", "check"])
            .env("RALON_HOME", &self.home)
            .current_dir(&self.root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to run ralon");
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(request.as_bytes())
            .expect("failed to send the request");
        child
            .wait_with_output()
            .expect("failed to read the decision")
    }

    /// Whether an ordinary write to `relative` gets through.
    ///
    /// Run in a separate shell process on purpose: the whole claim being tested
    /// is that enforcement reaches a process Ralon never started and that has
    /// never heard of it. Reading the file back afterwards is the assertion —
    /// the shell's exit code is not evidence of anything.
    fn writable(&self, relative: &str) -> bool {
        let before = self.contents(relative);
        let marker = "OVERWRITTEN-BY-AN-AGENT";
        shell(&self.root, &redirect(marker, &self.path(relative)));
        let after = self.contents(relative);
        if after.trim() == marker {
            // Put it back, so one probe does not change the outcome of the next.
            let _ = fs::write(self.path(relative), before);
            return true;
        }
        false
    }

    /// Whether a new file can be created at `relative`.
    fn creatable(&self, relative: &str) -> bool {
        let path = self.path(relative);
        let _ = fs::remove_file(&path);
        shell(&self.root, &redirect("NEW", &path));
        let created = path.is_file();
        let _ = fs::remove_file(&path);
        created
    }
}

/// A shell command, in the platform's own shell, outside Ralon entirely.
///
/// `raw_arg` on Windows, not `arg`. `Command` quotes arguments the way a C
/// runtime expects, escaping an embedded `"` as `\"` — and `cmd.exe` does not
/// parse its command line that way, so it sees a literal backslash and the
/// redirect never happens. The attack then does nothing, the file is unchanged,
/// and a test that reads the file back concludes it was refused. Every
/// enforcement assertion in this file would have passed against a Ralon that
/// enforced nothing at all.
fn shell(directory: &Path, command: &str) {
    #[cfg(windows)]
    let mut process = {
        use std::os::windows::process::CommandExt;
        let mut process = Command::new("cmd");
        process.raw_arg("/c").raw_arg(command);
        process
    };

    #[cfg(not(windows))]
    let mut process = {
        let mut process = Command::new("sh");
        process.args(["-c", command]);
        process
    };

    let _ = process.current_dir(directory).output();
}

fn redirect(text: &str, path: &Path) -> String {
    format!("echo {text}> \"{}\"", path.display())
}

/// Quotes a path for the config file. A Windows path is full of backslashes,
/// which YAML reads as escapes inside double quotes and leaves alone in single.
fn yaml(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// Strips the `\\?\` a canonicalized Windows path carries, so the result is
/// something an ordinary shell can open.
fn plain(path: &Path) -> PathBuf {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process was killed")
}

// ---------------------------------------------------------------------------
// Discovery and policy handling. Platform-independent in shape, but every one
// of these drives a real supervisor pass, and on Linux there is no supervisor to
// drive — `daemon` refuses there, which `without_a_supervisor` covers instead.
// ---------------------------------------------------------------------------

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_policy_outside_every_declared_scope_is_never_enforced() {
    let machine = Machine::new();
    // A scope that exists but holds no projects.
    let empty = machine.code.join("in-scope");
    fs::create_dir_all(&empty).unwrap();
    machine.configure(&[empty]);

    // A repository with a perfectly good policy, somewhere nobody declared —
    // the shape of an `agent.lock` that arrived inside a downloaded archive.
    let elsewhere = machine.repository("out-of-scope", Some(POLICY));

    machine.tick();
    assert!(
        !machine.recorded().contains("out-of-scope"),
        "a policy outside every scan root was picked up: {}",
        machine.recorded()
    );

    // And says so rather than looking protected.
    let status = elsewhere.ralon(&["status"]);
    assert!(
        !stdout(&status).contains("enforced by the supervisor"),
        "{}",
        stdout(&status)
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_malformed_policy_is_reported_and_never_looks_enforced() {
    let machine = Machine::new();
    let repository = machine.repository("broken", Some("version: 1\nprotect: [oh no: ["));

    let tick = machine.tick();
    // Not a crash, and not silence.
    assert_eq!(code(&tick), 0, "{}", stderr(&tick));
    let reported = format!("{}{}", stdout(&tick), stderr(&tick));
    assert!(
        reported.contains("cannot enforce"),
        "a policy that does not parse was not reported: {reported}"
    );
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );

    // The crucial half: it must not read as protected anywhere. `status` cannot
    // even parse the policy, so it fails and names the line — which is a better
    // answer than a summary, and is emphatically not a clean report.
    let status = repository.ralon(&["status"]);
    assert_ne!(
        code(&status),
        0,
        "status was happy about a policy it cannot read: {}",
        stdout(&status)
    );
    assert!(
        stderr(&status).contains("failed to parse"),
        "{}",
        stderr(&status)
    );
    assert!(!stdout(&status).contains("enforced"), "{}", stdout(&status));
}

#[test]
#[cfg(any(windows, target_os = "macos"))]
fn a_malformed_policy_locks_nothing_rather_than_locking_everything() {
    // "Fail safely" has two readings and only one of them is right. A policy
    // that cannot be parsed names no paths, so there is nothing to protect and
    // nothing is protected — loudly. Falling *closed* here would mean freezing
    // a repository on the strength of a file nobody could read, which is a
    // worse outcome than the one being avoided and impossible to diagnose.
    //
    // The case where this would matter most cannot arise: a workspace that is
    // already enforced has its own `agent.lock` locked, so nothing can corrupt
    // it while enforcement is in place.
    let machine = Machine::new();
    let repository = machine.repository("broken", Some("version: 1\nprotect: [oh no: ["));
    machine.tick();

    assert!(
        repository.writable(".env"),
        "an unreadable policy left files locked, with no way to find out why"
    );
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_broken_policy_that_gets_fixed_is_picked_up() {
    let machine = Machine::new();
    let repository = machine.repository("fixed", Some("version: 9\nprotect: []"));

    machine.tick();
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );

    repository.declare(POLICY);
    machine.tick();
    assert!(
        machine.recorded().contains("enforced"),
        "a corrected policy was not picked up: {}",
        machine.recorded()
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_policy_file_carries_no_machine_state() {
    // `agent.lock` is committed to Git and shared between machines, so the
    // supervisor must never write to it. Everything it learns lives in its own
    // state directory.
    let machine = Machine::new();
    let repository = machine.repository("portable", Some(POLICY));

    machine.tick();

    assert_eq!(
        repository.contents("agent.lock"),
        POLICY,
        "the supervisor modified agent.lock"
    );
    let recorded = machine.recorded();
    assert!(
        recorded.contains("portable"),
        "state should live in the state directory: {recorded}"
    );
}

// ---------------------------------------------------------------------------
// Linux, where the honest answer is no.
// ---------------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "macos")))]
mod without_a_supervisor {
    use super::*;

    #[test]
    fn install_refuses_and_explains_why() {
        let machine = Machine::new();
        let attempt = machine.ralon(&["install", "--scope", machine.code.to_str().unwrap()]);

        assert_ne!(
            code(&attempt),
            0,
            "install claimed to work: {}",
            stdout(&attempt)
        );
        let said = stderr(&attempt);
        // Not merely "unsupported" — the reason, and what to do instead.
        assert!(said.contains("inherited"), "{said}");
        assert!(said.contains("ralon run"), "{said}");
        assert!(
            !said.contains("systemd"),
            "a systemd unit would start and enforce nothing: {said}"
        );
    }

    #[test]
    fn the_daemon_refuses_to_run_rather_than_tracking_files_it_cannot_protect() {
        let machine = Machine::new();
        let _repository = machine.repository("app", Some(POLICY));

        let attempt = machine.tick();
        assert_ne!(
            code(&attempt),
            0,
            "the daemon started on a platform where it can enforce nothing: {}",
            stdout(&attempt)
        );
        assert!(
            !machine.home.join("workspaces.json").exists(),
            "a workspace was recorded as being looked after by nothing"
        );
    }

    #[test]
    fn run_is_untouched_and_is_still_the_answer_here() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        let planned = repository.ralon(&["run", "--dry-run", "--", "sh", "-c", "true"]);
        assert_eq!(code(&planned), 0, "{}", stderr(&planned));
        assert!(
            stdout(&planned).contains("read-only"),
            "{}",
            stdout(&planned)
        );
    }
}

// ---------------------------------------------------------------------------
// Windows and macOS, where a background process can impose a restriction.
// ---------------------------------------------------------------------------

#[cfg(any(windows, target_os = "macos"))]
mod with_a_supervisor {
    use super::*;

    #[test]
    fn a_repository_with_a_policy_becomes_enforced_with_nothing_run_inside_it() {
        let machine = Machine::new();
        let repository = machine.repository("app", None);

        // No policy yet: an ordinary project, ordinary permissions.
        machine.tick();
        assert!(
            repository.writable(".env"),
            "a project with no policy should be writable"
        );

        // This is the entire user-facing gesture. No `ralon init`, no wrapper.
        repository.declare(POLICY);
        machine.tick();

        assert!(
            !repository.writable(".env"),
            ".env was still writable after the policy appeared"
        );
        assert!(
            !repository.writable("src/index.tsx"),
            "src/index.tsx was still writable"
        );
        assert!(
            !repository.writable("config/db.yaml"),
            "a file inside a protected directory was still writable"
        );
        assert!(
            !repository.writable("agent.lock"),
            "the policy could rewrite itself"
        );
        // And nothing beyond the policy was touched.
        assert!(
            repository.writable("src/App.tsx"),
            "an unprotected file stopped being writable"
        );
    }

    #[test]
    fn an_enforced_project_is_given_the_agent_hook() {
        // Without this the enforcement still holds and the *message* does not:
        // the agent is handed `EBUSY: resource busy or locked`, decides the file
        // is corrupt, and retries, renames around it and shells out before
        // giving up. Observed in a real session, which is why the supervisor
        // installs the hook rather than leaving it to be discovered.
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        // Hooks are written only for agents the project or machine uses, so the
        // project has to look like it uses Claude for this to assert on Claude's
        // file rather than on whatever the test machine happens to have set up.
        // A bare `.claude` directory is exactly the marker detection looks for.
        fs::create_dir_all(repository.path(".claude")).unwrap();
        machine.tick();

        let settings = repository.contents(".claude/settings.json");
        assert!(
            settings.contains("ralon hook check"),
            "no hook was installed: {settings}"
        );

        // The message the agent actually receives, for the tool spelling that
        // slipped past the old hand-written matcher.
        let request = format!(
            r#"{{"tool_name":"Update","tool_input":{{"file_path":"{}"}}}}"#,
            repository
                .path(".env")
                .display()
                .to_string()
                .replace('\\', "\\\\")
        );
        let refused = repository.hook(&request);
        assert_eq!(code(&refused), 2, "the hook allowed a protected write");
        let said = stdout(&refused);
        assert!(said.contains("protected by Ralon"), "{said}");
        assert!(
            said.contains("github.com/stoneware-dev/Ralon"),
            "the refusal carries no link back to the project: {said}"
        );
        assert!(
            !said.contains("EBUSY"),
            "the refusal repeats the raw OS error it exists to replace: {said}"
        );
    }

    #[test]
    fn no_hooks_leaves_the_project_alone_but_still_enforces_it() {
        let machine = Machine::new();
        machine.set_hooks(false);
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        assert!(
            !repository.path(".claude").exists(),
            "the supervisor wrote agent configuration after being told not to"
        );
        assert!(
            !repository.writable(".env"),
            "enforcement was skipped along with the hooks"
        );
    }

    #[test]
    fn adding_a_scope_enforces_the_policies_already_under_it() {
        let machine = Machine::new();
        // A second tree, nowhere near the configured scope. Stands in for
        // `D:\Projects` on a machine whose only scope is a home directory on C:.
        let elsewhere = machine.elsewhere("side");
        let repository = machine.repository_in(&elsewhere, "app", Some(POLICY));

        machine.tick();
        assert!(
            repository.writable(".env"),
            "a project outside every scope was enforced anyway"
        );

        let added = machine.ralon(&["scope", "add", elsewhere.to_str().unwrap()]);
        assert_eq!(code(&added), 0, "{}", stderr(&added));
        // Enforced by the time the command returns, not at the next sweep.
        assert!(
            !repository.writable(".env"),
            "`scope add` returned before enforcing what it had just taken on"
        );
    }

    #[test]
    fn removing_a_scope_releases_its_projects() {
        let machine = Machine::new();
        let elsewhere = machine.elsewhere("side");
        let repository = machine.repository_in(&elsewhere, "app", Some(POLICY));

        machine.ralon(&["scope", "add", elsewhere.to_str().unwrap()]);
        assert!(!repository.writable(".env"));

        let removed = machine.ralon(&["scope", "remove", elsewhere.to_str().unwrap()]);
        assert_eq!(code(&removed), 0, "{}", stderr(&removed));
        assert!(
            repository.writable(".env"),
            "dropping a scope left its projects locked with nothing watching them"
        );
        assert!(
            !machine.recorded().contains("side"),
            "a released project is still recorded: {}",
            machine.recorded()
        );
    }

    #[test]
    fn several_scopes_are_enforced_at_once_and_independently() {
        let machine = Machine::new();
        let one = machine.elsewhere("one");
        let two = machine.elsewhere("two");
        let first = machine.repository_in(&one, "app", Some(POLICY));
        let second = machine.repository_in(&two, "app", Some(POLICY));

        machine.ralon(&["scope", "add", one.to_str().unwrap()]);
        machine.ralon(&["scope", "add", two.to_str().unwrap()]);
        assert!(!first.writable(".env"), "scope one was not enforced");
        assert!(!second.writable(".env"), "scope two was not enforced");

        // Dropping one leaves the other exactly as it was.
        machine.ralon(&["scope", "remove", one.to_str().unwrap()]);
        assert!(first.writable(".env"), "scope one was not released");
        assert!(
            !second.writable(".env"),
            "removing one scope released another"
        );
    }

    #[test]
    fn a_project_outside_every_scope_is_told_so_rather_than_ignored() {
        let machine = Machine::new();
        let elsewhere = machine.elsewhere("side");
        let repository = machine.repository_in(&elsewhere, "app", Some(POLICY));
        machine.tick();

        let status = repository.ralon(&["status"]);
        let said = stdout(&status);
        assert!(said.contains("outside every scope"), "{said}");
        assert!(said.contains("NOT protected"), "{said}");
        // And the way out, with a real directory in it rather than a placeholder.
        assert!(
            said.contains("ralon scope add"),
            "the fix was not offered: {said}"
        );
    }

    #[test]
    fn scopes_fold_rather_than_overlapping() {
        let machine = Machine::new();
        let outer = machine.elsewhere("outer");
        let inner = outer.join("inner");
        fs::create_dir_all(&inner).unwrap();

        machine.ralon(&["scope", "add", inner.to_str().unwrap()]);
        // Adding the parent absorbs the child rather than watching both.
        let broader = machine.ralon(&["scope", "add", outer.to_str().unwrap()]);
        assert!(
            stdout(&broader).contains("absorbed"),
            "{}",
            stdout(&broader)
        );

        let listed = stdout(&machine.ralon(&["scope", "list"]));
        assert!(listed.contains("outer"), "{listed}");
        assert_eq!(
            listed.matches("inner").count(),
            0,
            "the absorbed scope is still listed: {listed}"
        );

        // And the child is now covered by the parent, so re-adding is a no-op.
        let again = machine.ralon(&["scope", "add", inner.to_str().unwrap()]);
        assert!(
            stdout(&again).contains("already covered"),
            "{}",
            stdout(&again)
        );
    }

    #[test]
    fn equivalent_spellings_of_a_path_are_one_scope() {
        let machine = Machine::new();
        let elsewhere = machine.elsewhere("side");

        machine.ralon(&["scope", "add", elsewhere.to_str().unwrap()]);

        // The same directory, spelled differently. Each must resolve to the
        // scope that already exists rather than adding a second one that does
        // not recognise the first's repositories.
        let indirect = elsewhere.join("..").join(
            elsewhere
                .file_name()
                .expect("the scope has a final component"),
        );
        let again = machine.ralon(&["scope", "add", indirect.to_str().unwrap()]);
        assert!(
            stdout(&again).contains("already covered"),
            "`{}` was treated as a different directory: {}",
            indirect.display(),
            stdout(&again)
        );

        #[cfg(windows)]
        {
            let shouted = elsewhere.to_str().unwrap().to_uppercase();
            let cased = machine.ralon(&["scope", "add", &shouted]);
            assert!(
                stdout(&cased).contains("already covered"),
                "casing made a second scope on a case-insensitive filesystem: {}",
                stdout(&cased)
            );
        }
    }

    #[test]
    fn removing_a_directory_inside_a_scope_is_refused_with_a_reason() {
        let machine = Machine::new();
        let elsewhere = machine.elsewhere("side");
        let inner = elsewhere.join("app");
        fs::create_dir_all(&inner).unwrap();
        machine.ralon(&["scope", "add", elsewhere.to_str().unwrap()]);

        let attempt = machine.ralon(&["scope", "remove", inner.to_str().unwrap()]);
        assert_ne!(code(&attempt), 0, "a non-scope was reported as removed");
        assert!(
            stderr(&attempt).contains("is inside"),
            "{}",
            stderr(&attempt)
        );
        // And it really did not remove anything.
        assert!(
            stdout(&machine.ralon(&["scope", "list"])).contains("side"),
            "the scope was dropped anyway"
        );
    }

    // A note on drive letters, because the obvious test here is a trap.
    //
    // `subst X: <dir>` makes a real drive letter without administrator, and the
    // first version of these tests used it. It proves less than it looks: a
    // substituted path canonicalizes straight back to its backing directory, so
    // `X:\Projects\app` is stored as `C:\...\backing\Projects\app` and every
    // assertion about "another drive" is really about another directory on the
    // same one. A test that passes for the wrong reason is worse than no test.
    //
    // So the split is deliberate. The cross-drive *semantics* — that `D:\` is
    // never a prefix of `C:\`, that scopes on separate drives fold and remove
    // independently — are unit-tested in `supervisor::registry` against literal
    // `C:\`, `D:\` and `E:\` paths, where the comparison is pure and exact. The
    // *wiring* is tested here against independent directory trees, which is the
    // same code path with a real supervisor behind it. Running the whole suite
    // with `TMP` pointed at a second physical drive exercises both at once.

    #[test]
    fn a_scope_whose_directory_disappears_does_not_disturb_the_others() {
        let machine = Machine::new();
        let removable = machine.elsewhere("removable");
        machine.ralon(&["scope", "add", removable.to_str().unwrap()]);

        let still_here = machine.repository("local", Some(POLICY));
        machine.tick();
        assert!(!still_here.writable(".env"));

        // The shape of an unplugged drive or an unmounted share: the scope is
        // configured and the directory behind it is gone.
        fs::remove_dir_all(&removable).unwrap();

        let tick = machine.tick();
        assert_eq!(code(&tick), 0, "{}", stderr(&tick));
        assert!(
            !still_here.writable(".env"),
            "an unreachable scope released a project under a scope that is fine"
        );
        // And it is reported rather than looking like an empty scope.
        let listed = stdout(&machine.ralon(&["scope", "list"]));
        assert!(listed.contains("unreachable"), "{listed}");
    }

    /// Renaming a directory on the way to a protected file, and putting a
    /// different file back at that path.
    ///
    /// The bytes surviving under a new name is no comfort: what matters is what
    /// is at the path the policy named, because that is what every build and
    /// deploy reads. Windows pins each ancestor with a directory handle that
    /// shares neither write nor delete, so the rename fails before any of this
    /// gets started — but the assertion is on the *content at the protected
    /// path*, so a regression in pinning fails here rather than passing on the
    /// strength of the rename alone.
    #[test]
    #[cfg(windows)]
    fn an_ancestor_cannot_be_renamed_and_substituted() {
        let machine = Machine::new();
        let repository = machine.repository_in(
            &machine.code.clone(),
            "nested",
            Some("version: 1\nprotect:\n  - src/deep/secret.txt\n"),
        );
        fs::create_dir_all(repository.path("src/deep")).unwrap();
        fs::write(repository.path("src/deep/secret.txt"), "ORIGINAL").unwrap();
        machine.tick();

        for attack in [
            // rename an ancestor, then rebuild it and write a different file
            "ren src\\deep moved && mkdir src\\deep && echo PWNED> src\\deep\\secret.txt",
            // the same one level up
            "ren src src2 && mkdir src\\deep && echo PWNED> src\\deep\\secret.txt",
            // build the replacement first and swap it in
            "mkdir decoy && echo PWNED> decoy\\secret.txt && move /y src\\deep old && move /y decoy src\\deep",
            // remove the ancestor outright and rebuild it
            "rmdir /s /q src\\deep && mkdir src\\deep && echo PWNED> src\\deep\\secret.txt",
            // a junction pointing somewhere the policy never named
            "mkdir evil && echo PWNED> evil\\secret.txt && rmdir /s /q src\\deep && mklink /J src\\deep evil",
            // move the ancestor out of the project entirely
            "move /y src\\deep ..\\stolen",
        ] {
            shell(&repository.root, attack);
            assert_eq!(
                repository.contents("src/deep/secret.txt"),
                "ORIGINAL",
                "`{attack}` put different content at the protected path"
            );
        }
    }

    #[test]
    fn a_protected_directory_refuses_new_entries() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        assert!(
            !repository.creatable("config/slipped-in.yaml"),
            "a new file was created inside a protected directory"
        );
        assert!(
            repository.creatable("src/allowed.tsx"),
            "a new file could not be created in an unprotected directory"
        );
    }

    #[test]
    fn removing_the_policy_releases_the_workspace() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable(".env"));

        // The policy protects itself, so it cannot simply be deleted — which is
        // the point of it. `pause` is the supported way to get it back.
        assert!(
            repository
                .ralon(&["pause", "--indefinitely"])
                .status
                .success(),
            "pause failed"
        );
        repository.undeclare();

        machine.tick();
        assert!(
            repository.writable(".env"),
            "the workspace stayed enforced after its policy was deleted"
        );
        assert!(
            !machine.recorded().contains("\"app\""),
            "a workspace with no policy is still recorded: {}",
            machine.recorded()
        );
    }

    #[test]
    fn a_policy_deleted_while_the_supervisor_was_down_is_still_released() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // Everything stops — the supervisor and the enforcement with it — and
        // the repository is deleted before anything starts again. The record in
        // the state directory is the only thing that still knows this workspace
        // existed.
        repository.ralon(&["guard", "--stop"]);
        repository.undeclare();

        let tick = machine.tick();
        assert_eq!(code(&tick), 0, "{}", stderr(&tick));
        assert!(
            !machine.recorded().contains("app"),
            "a deleted workspace was never cleaned up: {}",
            machine.recorded()
        );
        assert!(repository.writable(".env"), ".env stayed locked");
    }

    #[test]
    fn two_repositories_are_enforced_at_once_and_do_not_interfere() {
        let machine = Machine::new();
        let first = machine.repository("one", Some(POLICY));
        let second = machine.repository("two", Some("version: 1\nprotect:\n  - src/index.tsx\n"));
        machine.tick();

        // Each gets exactly its own policy, not the other's.
        assert!(!first.writable(".env"), "one/.env was writable");
        assert!(!first.writable("src/index.tsx"), "one/src/index.tsx");
        assert!(!second.writable("src/index.tsx"), "two/src/index.tsx");
        assert!(
            second.writable(".env"),
            "two/.env is not in two's policy and must stay writable"
        );

        // And releasing one leaves the other alone.
        assert!(second.ralon(&["pause", "--indefinitely"]).status.success());
        assert!(second.writable("src/index.tsx"), "two was not released");
        assert!(
            !first.writable("src/index.tsx"),
            "pausing one repository released another"
        );
    }

    #[test]
    fn a_repository_cloned_after_setup_is_picked_up() {
        let machine = Machine::new();
        let _existing = machine.repository("old", Some(POLICY));
        machine.tick();

        // The flow the whole feature exists for: the machine was set up once,
        // and this repository did not exist at the time.
        let cloned = machine.repository("cloned-later", Some(POLICY));
        machine.tick();

        assert!(
            !cloned.writable(".env"),
            "a repository cloned after install was not protected"
        );
    }

    #[test]
    fn restarting_the_supervisor_changes_nothing() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        machine.tick();
        let after_first = machine.recorded();

        // Each `daemon --once` is a fresh process reading the state back from
        // disk, which is exactly what a restart is.
        let second = machine.tick();
        let third = machine.tick();

        assert_eq!(code(&second), 0, "{}", stderr(&second));
        assert!(
            stdout(&third).contains("nothing to change"),
            "a restart re-did work that was already done: {}",
            stdout(&third)
        );
        assert_eq!(
            after_first,
            machine.recorded(),
            "the recorded state drifted across restarts"
        );
        assert!(
            !repository.writable(".env"),
            "enforcement lapsed on restart"
        );
    }

    #[test]
    fn enforcement_is_restored_after_the_machine_restarts() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable(".env"));

        // A reboot, faithfully: whatever was holding the files lets go, and the
        // state directory still says the workspace is enforced. On Windows that
        // is what actually happens — the guard is a process and processes do not
        // survive a restart. A supervisor that believed its own notes here would
        // come up, agree everything was fine, and protect nothing.
        repository.ralon(&["guard", "--stop"]);
        assert!(
            repository.writable(".env"),
            "the simulated reboot did not actually release anything, \
             so this test would pass without proving anything"
        );

        machine.tick();
        assert!(
            !repository.writable(".env"),
            "enforcement was not restored after a restart"
        );
    }

    #[test]
    fn enforcement_holds_against_many_agents_writing_at_once() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // Twelve unrelated processes, none of them started by Ralon, all
        // hammering the same protected paths at the same time.
        let root = repository.root.clone();
        let workers: Vec<_> = (0..12)
            .map(|index| {
                let root = root.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        for target in [".env", "src/index.tsx", "agent.lock"] {
                            shell(
                                &root,
                                &redirect(&format!("AGENT{index}"), &root.join(target)),
                            );
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        assert_eq!(repository.contents(".env"), "SECRET=original");
        assert_eq!(repository.contents("src/index.tsx"), "original");
        assert_eq!(repository.contents("agent.lock"), POLICY);
    }

    #[test]
    fn enforcement_holds_however_the_write_is_attempted() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // A hook covers an agent's own edit tools. None of these go anywhere
        // near one: a shell redirect, a delete, a rename, a rename *over* the
        // target, and a script written to disk and executed.
        let env = repository.path(".env");
        let index = repository.path("src/index.tsx");
        let decoy = repository.path("src/decoy.tsx");
        fs::write(&decoy, "DECOY").unwrap();

        #[cfg(windows)]
        let attacks = vec![
            format!("echo X> \"{}\"", env.display()),
            format!("del /f /q \"{}\"", env.display()),
            format!("move /y \"{}\" \"{}.bak\"", env.display(), env.display()),
            format!("move /y \"{}\" \"{}\"", decoy.display(), index.display()),
            format!("type \"{}\" > \"{}\"", decoy.display(), env.display()),
        ];
        #[cfg(not(windows))]
        let attacks = vec![
            format!("echo X> '{}'", env.display()),
            format!("rm -f '{}'", env.display()),
            format!("mv '{}' '{}.bak'", env.display(), env.display()),
            format!("mv '{}' '{}'", decoy.display(), index.display()),
            format!("cat '{}' > '{}'", decoy.display(), env.display()),
        ];

        for attack in &attacks {
            shell(&repository.root, attack);
            assert_eq!(
                repository.contents(".env"),
                "SECRET=original",
                "`{attack}` got through to .env"
            );
            assert_eq!(
                repository.contents("src/index.tsx"),
                "original",
                "`{attack}` got through to src/index.tsx"
            );
        }

        // The same again, from a script file rather than an inline command, so
        // nothing about this depends on how the shell was invoked.
        #[cfg(windows)]
        let (script, runner) = ("attack.cmd", "cmd");
        #[cfg(not(windows))]
        let (script, runner) = ("attack.sh", "sh");
        let script = repository.root.join(script);
        fs::write(&script, attacks.join("\n")).unwrap();

        let mut process = Command::new(runner);
        #[cfg(windows)]
        process.arg("/c");
        process.arg(&script);
        let _ = process.current_dir(&repository.root).output();

        assert_eq!(repository.contents(".env"), "SECRET=original");
        assert_eq!(repository.contents("src/index.tsx"), "original");
    }

    #[test]
    fn pause_hands_the_policy_back_and_resume_takes_it_again() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable("agent.lock"));

        let paused = repository.ralon(&["pause", "--indefinitely"]);
        assert_eq!(code(&paused), 0, "{}", stderr(&paused));
        // The command must not return until the file is genuinely writable, or
        // `ralon pause && $EDITOR agent.lock` races it.
        assert!(
            repository.writable("agent.lock"),
            "pause returned before releasing the policy file"
        );

        // A pause is a hole in the protection and has to be visible as one.
        let status = repository.ralon(&["status"]);
        assert!(
            stdout(&status).contains("PAUSED"),
            "a paused workspace did not say so: {}",
            stdout(&status)
        );

        let resumed = repository.ralon(&["resume"]);
        assert_eq!(code(&resumed), 0, "{}", stderr(&resumed));
        assert!(
            !repository.writable("agent.lock"),
            "resume reported success without restoring enforcement"
        );
    }

    #[test]
    fn a_paused_workspace_is_not_re_enforced_until_it_expires() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        repository.ralon(&["pause", "--indefinitely"]);
        // The supervisor keeps running while a workspace is paused and must
        // leave it alone rather than immediately taking it back.
        machine.tick();
        assert!(
            repository.writable("agent.lock"),
            "a tick re-enforced a paused workspace"
        );

        // An expired pause is over without anyone doing anything: rewrite the
        // deadline into the past, which is what the clock would have done.
        let recorded = machine
            .recorded()
            .replace(r#""until": null"#, r#""until": 1"#);
        assert!(
            recorded.contains(r#""until": 1"#),
            "the deadline was never rewritten, so this test proves nothing: {recorded}"
        );
        fs::write(machine.home.join("workspaces.json"), recorded).unwrap();

        machine.tick();
        assert!(
            !repository.writable("agent.lock"),
            "a pause that had run out was not taken back"
        );
    }

    #[test]
    fn status_reports_the_supervisor_and_the_workspace_separately() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        let status = repository.ralon(&["status"]);
        let said = stdout(&status);
        // "A service is registered" and "this project is protected" are
        // different claims, and only the second one is about these files.
        assert!(said.contains("supervisor"), "{said}");
        assert!(said.contains("enforced by the supervisor"), "{said}");
    }
}

/// `ralon install --here` — one repository, not a directory of them.
///
/// Everything uses `--dry-run`, because the alternative is registering a real
/// logon task and deregistering the developer's own supervisor. What is under
/// test is which scope `--here` chooses, and the plan prints it.
#[cfg(any(windows, target_os = "macos"))]
mod covering_one_project {
    use super::*;

    fn plan(machine: &Machine, from: &Path, arguments: &[&str]) -> String {
        let output = Command::new(BINARY)
            .arg("--dir")
            .arg(from)
            .args(["install", "--dry-run"])
            .args(arguments)
            .env("RALON_HOME", &machine.home)
            .output()
            .expect("failed to run ralon");
        stdout(&output)
    }

    #[test]
    fn the_scope_is_the_project_and_not_the_home_directory() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        let said = plan(&machine, &repository.root, &["--here"]);
        assert!(
            said.contains(&format!("scope      {}", plain(&repository.root).display())),
            "{said}"
        );
        // The failure this flag exists to avoid: one repository asked for, the
        // whole home directory registered.
        assert_eq!(said.matches("scope      ").count(), 1, "{said}");
    }

    #[test]
    fn it_finds_the_project_from_a_subdirectory() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        // Run from `src/`. Scoping to the directory the command was typed in
        // would exclude agent.lock, which lives at the root — so the project
        // would be "covered" by a scope that cannot see its policy.
        let said = plan(&machine, &repository.path("src"), &["--here"]);
        assert!(
            said.contains(&format!("scope      {}", plain(&repository.root).display())),
            "{said}"
        );
    }

    #[test]
    fn without_it_a_directory_of_projects_is_still_the_default() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        let said = plan(
            &machine,
            &repository.root,
            &["--scope", machine.code.to_str().unwrap()],
        );
        assert!(
            said.contains(&format!("scope      {}", plain(&machine.code).display())),
            "{said}"
        );
    }

    #[test]
    fn naming_a_scope_and_asking_for_this_one_is_refused() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        let attempt = Command::new(BINARY)
            .arg("--dir")
            .arg(&repository.root)
            .args(["install", "--dry-run", "--here", "--scope"])
            .arg(&machine.code)
            .env("RALON_HOME", &machine.home)
            .output()
            .expect("failed to run ralon");

        // They mean opposite things; silently letting one win would register a
        // scope the person did not ask for.
        assert!(!attempt.status.success(), "{}", stdout(&attempt));
    }
}

// ---------------------------------------------------------------------------
// Where the supervisor's binary lives, which is a Windows problem specifically.
// ---------------------------------------------------------------------------

/// Windows will not delete the image of a running process, and the supervisor
/// runs all day. Registering it from wherever a package manager happened to put
/// the binary therefore made that package impossible to uninstall — reported
/// against `bun remove`, and the same for `pip uninstall` and `cargo install
/// --force`, none of which have any way to know a background process is holding
/// their file.
///
/// The control case is the point of this module. If the first test ever stops
/// failing to delete, then the platform has changed underneath the fix and the
/// second test is proving nothing.
#[cfg(windows)]
mod the_staged_binary {
    use super::*;

    /// A copy of `ralon.exe` where a package manager would have put it.
    fn package_copy(machine: &Machine) -> PathBuf {
        let directory = machine
            .home
            .parent()
            .unwrap()
            .join("node_modules/@stoneware-dev/win32-x64/bin");
        fs::create_dir_all(&directory).unwrap();
        let copy = directory.join("ralon.exe");
        fs::copy(BINARY, &copy).unwrap();
        copy
    }

    /// Runs `daemon` from `executable` and waits until it has taken the lock,
    /// so the assertions that follow are about a process that is really there.
    fn run_daemon(executable: &Path, home: &Path) -> std::process::Child {
        let child = Command::new(executable)
            .args(["daemon", "--home"])
            .arg(home)
            .spawn()
            .expect("failed to start the daemon");
        for _ in 0..100 {
            if home.join("supervisor.lock").exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        child
    }

    #[test]
    fn a_supervisor_running_from_the_package_makes_the_package_undeletable() {
        let machine = Machine::new();
        let copy = package_copy(&machine);

        let mut daemon = run_daemon(&copy, &machine.home);
        let refused = fs::remove_file(&copy);
        let _ = daemon.kill();
        let _ = daemon.wait();

        // The bug as reported: the file is still there, and the error says
        // nothing about a running process.
        assert!(
            refused.is_err(),
            "Windows allowed a running image to be deleted — the premise of the \
             staging fix no longer holds and `the_registration_never_points_into_a_\
             package_directory` is not testing anything"
        );
        assert!(copy.exists());
    }

    #[test]
    fn a_supervisor_running_from_the_staged_copy_leaves_the_package_deletable() {
        let machine = Machine::new();
        let copy = package_copy(&machine);

        // What `ralon install` now does before it registers anything.
        let staged = machine.home.join("bin/ralon.exe");
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::copy(&copy, &staged).unwrap();

        let mut daemon = run_daemon(&staged, &machine.home);
        let removed = fs::remove_file(&copy);
        let _ = daemon.kill();
        let _ = daemon.wait();

        // Asserted on the filesystem rather than on the result: the whole
        // reported symptom was a file that would not go away.
        assert!(removed.is_ok(), "{removed:?}");
        assert!(
            !copy.exists(),
            "the package manager's copy survived, so uninstalling the package \
             would still fail"
        );
    }

    #[test]
    fn install_registers_the_staged_copy_and_not_the_one_it_was_run_from() {
        let machine = Machine::new();
        let copy = package_copy(&machine);

        // `--dry-run` because registering a real logon task from a test would
        // deregister the developer's own supervisor. It prints the path it
        // would register, which is the claim under test.
        let planned = Command::new(&copy)
            .args(["install", "--dry-run", "--scope"])
            .arg(&machine.code)
            .env("RALON_HOME", &machine.home)
            .output()
            .expect("failed to run ralon");
        let said = stdout(&planned);

        assert!(
            said.contains(&machine.home.join("bin").display().to_string()),
            "the plan does not name the staged copy: {said}"
        );
        assert!(
            !said
                .lines()
                .any(|line| { line.starts_with("supervisor") && line.contains("node_modules") }),
            "the plan would register a path inside a package directory: {said}"
        );
    }
}
