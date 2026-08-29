# Changelog

Versions follow the rules in `publishing.md`: while on `0.x` the minor is the
breaking position, and a change to what a policy protects is breaking even when
the CLI is untouched.

## 0.1.7

Four bugs reported from one Windows install. One was hiding a fifth, and fixing
the fourth created a sixth — found before release, on the machine that reported
the others.

None of them touched enforcement itself; they were all about the machinery
around it — how the supervisor is registered, how a guard is found, how the
package is removed, and whether the agent hooks can run at all. Anyone who
installed `0.1.6` on Windows should run `ralon uninstall` and reinstall, because
the registration written then points at the package manager's copy of the
binary.

### Changed

- **`version:` is no longer required in `agent.lock`.** It bought a line of
  ceremony in every policy file and no information — "no version stated" says
  *version 1* just as well, and stays true forever. Files that state it keep
  working unchanged, `version: 2` is still rejected, and `ralon init` no longer
  writes it. What actually validates a policy is that unknown keys are refused,
  which is why dropping this weakens nothing: `protects:` is still an error
  rather than a policy protecting nothing.

  One case needed closing to make it safe. With every field defaulting, an
  **empty** `agent.lock` parsed as a valid policy protecting nothing, and the
  supervisor would have reported the project `enforced` — so `touch agent.lock`,
  a truncating crash or a bad merge would have told a developer they were
  covered while every path was writable. An empty or comment-only policy is now
  refused with the paths to add.

- **`ralon scope add` warns about a network path.** A session-0 supervisor has no
  network credentials, so it cannot discover projects on a mapped drive or a UNC
  path. `ralon guard` and `ralon run` are unaffected.

### Added

- **`ralon install --here`** — cover a single repository rather than a directory
  of them. For one project you want protected across reboots without declaring
  where all your code lives. It scopes to the project root even when run from a
  subdirectory, so `agent.lock` is always inside the scope.
- **The supervisor protects its own binary and its own scopes.** Both sit in a
  user-writable directory by design (nothing here asks for administrator), which
  left two silent paths: replace `bin/ralon.exe` and own the supervisor at the
  next logon, or delete a line from `config.yaml` and unprotect every project
  under that scope. A running supervisor now holds both — rename, overwrite,
  delete and scope-wipe are all refused. `ralon scope add` still works; it asks
  the supervisor to stand down, writes, and restarts it, with the guards holding
  their projects throughout. Every scope change made through Ralon is written to
  the log with what the scopes were before. This is not protection while Ralon
  is stopped, and it does not stop an agent running `ralon scope remove` — there
  is no password by design, and that is the same boundary that lets an agent
  kill a guard. See `security.md`.
- **Hard-link warnings on Windows.** The check existed but returned an empty
  list there, so the one platform whose enforcement is entirely about holding
  file handles never warned about a second name for the same bytes. NTFS has
  hard links and `mklink /H` needs no privilege.
- **The supervisor records what enforcement does not cover.** Hard links and
  exposed ancestors were reported by `check` and `status` — commands a person
  runs — while under the supervisor nobody runs anything. They now go to the log
  as each project starts being enforced.
- **A refusal names every protected path in the request, not just the first.** A
  tool call touching two protected files was refused with one of them named, so
  an agent correcting itself was refused again for the second on the next
  attempt and the third on the one after — a round trip per protected file, each
  denial looking like a fresh failure. All of them are now listed, in the prose
  and in a `protectedPaths` array (`{"path", "pattern"}`) for agents that would
  rather read a field than a sentence. The refusal also now says that nothing in
  the call was modified — *including* the unprotected paths that shared it — and
  to re-issue it without the protected ones, which is the thing an agent
  otherwise has to guess. What has not changed: a call naming any protected path
  is still refused as a whole, because Ralon cannot apply two edits out of three
  and guessing that a tool applies them independently would write a protected
  file. Separate tool calls remain independent — `edit A`, `edit .env`, `edit B`
  allows A, refuses `.env`, allows B — and a refusal has never stopped an agent
  or released a guard.
- **Hooks are written only for the agents you use.** Installing a policy used to
  drop nine agent configuration files into every project — `.claude`, `.cursor`,
  `.codex` and six more — regardless of which tools you have. The new default,
  `--agent auto`, writes only the agents with a configuration directory in the
  project or your home directory, so a repo opened with Cursor gets one file, not
  nine to explain in review. `--agent all` still forces every one for a tool you
  have not opened the project with yet; detection falls back to all when it finds
  nothing, so a project is never left without the message. Copilot is written only
  under `all` — its one marker, `.github`, is present in too many repositories to
  mean anything. Which agents are configured changes only who gets the *message*;
  enforcement is in the kernel and depends on no hook.

### Fixed

- **`ralon install` restarts a supervisor that is already running.** The logon
  task's `MultipleInstancesPolicy` is `IgnoreNew`, so `/Run` against a running
  task does nothing and reports success — an upgrade kept the *previous* binary
  supervising until the next logon while `ralon --version` reported the new one.

- **No console window at logon, or at `ralon install`.** The logon task ran with
  an interactive token, and a console program started by something without a
  console of its own gets a fresh, visible one. The `<Hidden>` setting the task
  already carried does not affect this and the code claimed it did — `Hidden`
  controls whether the task appears in the Task Scheduler list. The task now uses
  the `S4U` logon type, which runs it in session 0, where there is no desktop for
  a window to appear on. Machines whose policy withholds the batch logon right
  fall back to the old behaviour and say so rather than failing to install.
- **`ralon guard --stop`, `pause` and `status` now work across logon sessions.**
  Found while verifying the fix above, and the more serious of the two: a guard
  claimed its project with a `Local\` named event, which is scoped to one logon
  session, while the file locks it stood for are refused to every process on the
  machine. With the supervisor moved to session 0 this became visible —
  duplicate guards, `status` reporting `guard not running` about a running guard,
  and `pause` reporting a project released while its files stayed locked. The
  claim is now a named pipe, which is machine-wide and needs no privilege. A
  guard left over from before the upgrade is still released by `--stop`.
- **Uninstalling the ralon package works on Windows.** `install` registered the
  binary wherever it found itself, which for `npm`, `bun`, `pip` and `cargo`
  installs is inside that tool's own directory. Windows will not delete the image
  of a running process, so `bun remove`, `pip uninstall` and `cargo install
  --force` all failed on a file the package manager was certain it owned, with an
  error naming a permission problem rather than a running process. `install` now
  copies the executable into Ralon's state directory and registers the copy;
  nothing ever opens the package manager's file.
- **Removing the package no longer leaves a registration pointing at nothing.**
  The same change fixes it, since the registered path is one only `ralon
  uninstall` removes. For installs already in that state, `ralon status` now
  reports a registration whose binary is missing instead of describing it as
  healthy. No package manager can deregister it for you — npm stopped running
  `preuninstall` scripts, and `pip` and `cargo` never had an uninstall hook — so
  `ralon install` now says to run `ralon uninstall` first, and the README does
  too.
- **`ralon install` puts its own directory on PATH, so the agent hooks can
  run.** Every hook entry invokes `ralon hook check` — a name rather than a path,
  because those files get committed and an absolute path would be one
  developer's machine in everybody's repository. Whether that name resolved was
  entirely the package manager's doing, and staging the binary (above) made it
  possible for the package to be gone while the supervisor keeps running: nine
  installed hooks, none of which can start. The failure is silent in the worst
  way — a shell that cannot find `ralon` exits 1, no agent reads 1 as "deny", so
  the edit proceeds, the kernel refuses it, and the developer is handed
  `EBUSY: resource busy or locked` about a repository that is working exactly as
  intended.

  The directory is **appended**, so a package manager's copy still wins where
  there is one; that copy is the one that upgrades, and a staged snapshot
  shadowing it would make `ralon --version` wrong after every upgrade. Written
  through the registry rather than with `setx`, which truncates `PATH` at 1024
  characters, and preserving the value's `REG_EXPAND_SZ` type, so `%USERPROFILE%`
  entries keep expanding. `ralon uninstall` takes the entry back out, and neither
  writes anything at all when there is nothing to change. Windows only: a shell's
  `PATH` elsewhere lives in a startup file the developer maintains by hand, so
  the line to add is printed instead.

- **`status`, `hook install` and the supervisor now report a hook that cannot
  run.** Previously nothing did, on any platform, and every symptom pointed
  somewhere else. `status` explains what is lost — the message, not the
  protection — and says how to fix it.

### Security

No bypass of a protected path. Four weaknesses in what surrounds one, all on
Windows, all present since the supervisor arrived in `0.1.6`:

- **A guard could be shown as running when it was not — the claim squat.** "Is a
  guard running" was answered by whether its claim pipe existed, and the pipe's
  name is a hash of the project path computed in open source. So any process
  running as you could create a pipe of that name and hold nothing: `status`
  reported a running guard over a writable file, and — the real harm — the
  supervisor recorded the project `enforced` and never started a real guard,
  because the respawn's own check was the one being spoofed. Killing a guard and
  squatting its claim turned the documented, self-healing "a guard can be killed"
  into silent, permanent, mis-reported non-enforcement. `running` now opens
  `agent.lock` for writing and asks whether the file refuses it — a share-mode
  lock cannot be faked without holding the file, at which point the holder *is*
  protecting it. A same-user process can still deny protection (kill the guard,
  squat the name), but it now surfaces as a workspace the supervisor reports it
  cannot enforce, not one it falsely believes it holds. Regression test in
  `enforce/windows/guard.rs`; the pipe remains only as the `--stop` rendezvous.

- **Ralon's own binary and scope list were unprotected while it ran.** Replacing
  `bin\ralon.exe` took over the supervisor at the next logon; deleting a line
  from `config.yaml` unprotected every project under that scope at the next
  reconcile, with nothing reporting either. Both are now held. What remains, by
  design, is that anything running as you can call `ralon scope remove` — there
  is no password, and that is the same boundary that lets an agent kill a guard.
- **Hard links were never warned about on Windows.** `mklink /H` needs no
  privilege and NTFS has had hard links throughout, so on the one platform whose
  enforcement is holding file handles, a second writable name for a protected
  file went unmentioned by `check` and `status`. The files stayed locked through
  their protected name; the warning is what was missing.
- **Under the supervisor, nothing reported the warnings at all.** Hard links and
  exposed ancestors were printed by commands a person runs, and the supervisor
  runs none. They now go to `supervisor.log` as each project starts.

`ralon run` is unaffected by all four — it holds the locks in the process it
started and consults no claim to know they are held.

## 0.1.6

`agent.lock` becomes the thing that activates enforcement. Set the machine up
once with `ralon install`, and from then on a repository is protected because it
contains a policy file — no `ralon init`, no wrapper around the agent, nothing to
remember after a reboot, and repositories cloned later are covered by the same
setup.

Where that is not possible, this release says so instead of approximating it.
Linux gets a refusal with a reason; macOS gets a mechanism that is weaker than
`ralon run` and is labelled that way everywhere it appears.

### Added

- **`ralon scope add | list | remove`** — the directories your projects live in,
  managed on their own rather than only as an argument to `install`. Where Ralon
  is installed now has nothing to do with what it protects: a Windows developer
  whose code is on `D:\` runs `ralon scope add D:\Projects` and every repository
  under it is covered. `add` and `remove` reconcile before returning, so the
  projects really are enforced (or really are released) by the time the command
  finishes. Scopes are kept disjoint — one inside another reports as covered, one
  containing others absorbs them — and canonicalized, so `d:\projects` and
  `D:\Projects` cannot become two scopes that ignore each other's repositories.
- **`ralon install` names the drives no scope covers**, with the command to fix
  it. The first-run default is still the home directory, which is on `C:` — and
  the failure it used to produce was silent: write an `agent.lock` on `D:`, watch
  nothing happen, and have no reason to suspect that scopes exist.
- **`ralon install` / `ralon uninstall`** — registers a per-user background
  supervisor with the operating system: a Task Scheduler logon task on Windows, a
  launchd LaunchAgent on macOS. No administrator, no root, and it survives a
  reboot because the OS starts it. `--scope` names the directories your projects
  live in; the default is the home directory.
- **Each enforced project gets the agent hook**, so an agent that reaches a
  protected path is told "protected by Ralon", which file, and which pattern
  matched — with a link to the repository. Without it the agent is handed
  whatever its runtime made of the OS error, and `EBUSY: resource busy or
  locked` reads as a corrupt file: observed in a real session, where the agent
  retried, renamed around it, shelled out, and only worked out what was
  happening by reading `agent.lock` itself. `--no-hooks` opts out; enforcement
  does not depend on it.
- **`ralon pause` / `ralon resume`** — releases one project so its own policy can
  be edited, since `agent.lock` protects itself. A pause expires after fifteen
  minutes unless `--indefinitely` is given: a pause that is forgotten about is a
  project that stopped being protected without anyone deciding it should.
- **`ralon daemon`** — the supervisor itself, started by the service. `--once`
  does a single pass and prints what changed.
- **A macOS guard**, using `chflags uchg`. This **reverses an earlier decision**
  in this project not to implement it. The objection was to describing a
  narrowing as protection, and it was right; what changed is that a supervisor
  needs a mechanism it can *impose* on a process nobody started, and on macOS
  this is the entire list. So it is implemented and labelled: an agent can undo
  it with `chflags nouchg`, it does not pin ancestors, and it is not equivalent
  to process-level sandboxing. `ralon run` remains the guarantee there.
  `security.md` and `enforce/macos/immutable.rs` state the limits, and
  `tests/immutable.rs` asserts the weaknesses so the claims cannot drift.
- `ralon status` now answers "is the supervisor registered", "is it running" and
  "is *this project* protected" as three separate lines. The first two have a
  comfortable answer that means nothing about the third.
- `tests/supervisor.rs` — the full lifecycle against the real binary: a policy
  appearing and being removed, a malformed one, several repositories at once,
  twelve concurrent unrelated processes attacking, a supervisor restart, a
  simulated reboot, and writes attempted through shells and scripts rather than
  an agent's edit tools.

### Changed

- **`ralon install` fails on Linux**, with the reason and what to use instead.
  Every Linux mechanism is inherited by a process before it runs and cannot be
  applied to one already running, so a systemd user unit would start cleanly,
  report `active (running)`, and enforce nothing. `ralon run` is unchanged and
  remains stronger than any supervisor on any platform.
- `ralon guard` now resolves the backend a *guard* can use rather than the one
  `run` would pick. On macOS that is the difference between Seatbelt, which can
  only be inherited, and the immutable flag, which can be imposed.

### Fixed

- **The agent hooks were scoped by hand-written lists of tool names, and one of
  them was wrong.** Claude Code's matcher read `Write|Edit|MultiEdit|NotebookEdit`;
  an agent called a tool its own transcript displayed as `Update`, so the hook
  never ran and the refusal fell back to the raw OS error. Four agent files each
  carried their own list, which is four chances to miss a spelling and a silent
  failure every time. There is now one shared matcher built from *verbs* rather
  than product names, matching either case, covering every writing tool the nine
  supported agents are known to have — with a test that pins them. `Bash` and
  friends are still excluded, still deliberately: a hook cannot tell which paths
  a shell command will touch.
- **A release ran no tests.** `cargo test`, `clippy` and `fmt` lived only in
  `ci.yml`, which triggers on branches and pull requests — and a tag push is
  neither, so it never fired. A tag on a commit whose suite was red would pass
  `guard`, build five binaries, create a GitHub release, and sit one approval
  away from three permanent registries, with nothing on the page to suggest
  anything was wrong. `release.yml` now calls `ci.yml` as a reusable workflow
  before it builds anything, so the tests have one definition and cannot drift
  from what a pull request runs.
- **The approval gate showed the reviewer nothing to check.** It printed the tag
  they had just typed. It now writes a summary naming each registry, what will
  appear there, and why none of it can be taken back. (The gate itself is only
  real if the `release` environment has a required reviewer configured under
  Settings → Environments — a repository setting no workflow file can enforce,
  now stated in the workflow.)
- **`ralon guard --detach` never warned about a policy naming paths that are not
  on disk.** The foreground `ralon guard` did; the detached branch returned
  before reaching it. So `--detach` printed "every process on this machine is now
  refused those paths" over a list quietly one path shorter than the policy, and
  the developer had no way to find out. Found by the macOS CI job, and it was
  present on Windows too.
- **`ralon install` replaced the scope list instead of adding to it**, so
  re-running it to repair a service registration silently dropped every scope
  added since. It is now additive, and the home-directory default applies only on
  a genuinely first run.
- **A scope added while the supervisor was running was not watched.** The daemon
  held the registrations it started with, so a new drive waited up to a minute
  for the sweep — and appeared to work only because the state directory happened
  to sit under the one scope being watched. The state directory is now registered
  deliberately, and a write to `config.yaml` is what wakes the supervisor.
- **Filesystem notifications were acted on indiscriminately.** A registration is
  recursive and unfiltered, so a scope on a home directory reported every write
  under `AppData` and the supervisor reconciled on each one. Only `agent.lock`
  and `config.yaml` can change what should be enforced; the rest is ignored, and
  the periodic sweep now runs on a deadline rather than a timeout so that
  continuous activity cannot starve it.
- **The sweep descended into `AppData`**, which on Windows is most of a home
  directory by directory count and can hold no projects. It is skipped, along
  with `Windows`, `Program Files`, `ProgramData` and the recycle bin.
- **`install` reported every drive as uncovered**, including the one the scopes
  were on: a canonical Windows path is `\\?\C:\...`, which does not
  `starts_with("C:\")` under component-wise comparison.
- **The shared matcher was broader than it needed to be**, which cost a process
  on every matching tool call and, in some Windows terminal hosts, a console
  window that flashes and goes. `apply`, `save`, `modify`, `append`, `mkdir` and
  `touch` matched no agent tool that the remaining verbs did not already cover,
  and did match a great many MCP tools that touch no file at all. The matcher
  decides the *message* and not the *protection* — a write it never sees is
  still refused by the kernel — so speculating there buys nothing and is paid
  for on every call.
- **`schtasks` is now invoked with `CREATE_NO_WINDOW`.** A console program
  inherits its parent's console unless the parent has none, in which case
  Windows gives it a fresh visible one. Every caller runs from a terminal today,
  so this changes nothing today; it stops a window appearing the first time one
  is called from somewhere without a console.
- **A guard was reported as failed when it had actually started.** `guard
  --detach` waited three seconds for the background process to claim the project;
  a binary Windows has not scanned before takes about 2.9 seconds to reach its
  first instruction, which is the first run after every install and every
  upgrade. The wait is now thirty seconds, and the claim — a kernel object — is
  re-checked before any failure is recorded.
- **Two spellings of one directory were two projects.** The guard's claim is a
  hash of the project path, so a path reached by walking and the same path
  canonicalized did not refer to the same project. Workspace identity is now
  canonicalized where the path enters the system.
- Canonical Windows paths are no longer printed in their verbatim `\\?\` form.

### The ancestor-path question, answered

Asked directly: with `src/deep/secret.txt` protected and neither `src/` nor
`src/deep/` protected, can an agent manipulate an ancestor so the file ends up
somewhere else and something writable takes its place? Every backend was run
against the whole family — rename an ancestor, rename a grandparent, move it out
of the tree, delete and rebuild it, swap it for a decoy, symlink or junction over
it, rename the protected file itself, hard-link out and edit.

- **Linux (mount and Landlock), Windows (locks), macOS (Seatbelt): held**, all
  of them. Each pins the directories on the way to a protected path — as mount
  points, as held directory handles, as `literal` deny nodes — so the first
  `mv` fails and nothing that follows gets started. Five substitution attacks
  were added to `tests/enforcement.rs` and a Windows set to
  `tests/supervisor.rs`, all asserting on **the content at the protected path**
  rather than on the rename, so a regression in pinning cannot pass by refusing
  the rename alone.
- **macOS `immutable` — the guard and the supervisor — is exposed**, and it is a
  real substitution, not a cosmetic one: rename the ancestor, recreate it, and
  the declared path holds someone else's file while the original bytes sit
  immutable under a name nothing reads.

It is not fixed, and the reason is a property of the mechanism rather than a
decision to leave it: macOS has one flag meaning both "may not be renamed" and
"may not accept new entries". Pinning `src/` would stop the project gaining a
file in `src/`; pinning the project root — which every policy needs, since
`agent.lock` lives there — would stop it gaining a file anywhere. The other
backends can separate those two ideas and this one cannot.

What was added instead:

- **`audit.rs` reports the exposure before the guard starts**, naming the file,
  the unprotected ancestor, and the way to close it — protect the directory
  rather than the file inside it, since a protected directory carries the flag
  itself and cannot be renamed. `ralon status` repeats it, because the output of
  the command that started enforcement scrolled away days ago.
- **Three tests in `tests/immutable.rs` pin the boundary**: that the substitution
  succeeds today, that protecting the directory stops it, and that the warning
  fires only when the exposure is real. The first asserts a weakness on purpose —
  if it ever fails, the backend got stronger and this changelog, `security.md`
  and the README are all overstating the gap, which is still a bug.

### A note on the macOS tests

`tests/immutable.rs` had never run when it was written — there is no container
for macOS — and the first CI run failed five of its ten tests. Four were the
tests being wrong, in two ways worth recording.

`flagged()` ran `ls -ldO` and searched the output for `uchg`, and the temporary
directory was named `ralon-uchg-<pid>`. `ls` prints the path it was given, so
every path "carried the flag": three assertions failed and the rest passed for no
reason at all. It now asks `stat -f %Sf`, which prints the flags and nothing
else, and the directory no longer contains the name of the thing being tested
for.

The other was a real correction to the documentation. `immutable.rs` said
ancestors are not pinned, and a test asserted that renaming a protected
directory therefore succeeded. It does not: a protected directory carries the
flag in its own right, and an immutable directory cannot be renamed or removed.
The gap is narrower than claimed — it applies to ancestors that are not
themselves protected — and both halves now have a test.

### A note on the tests

The Windows attack helper in `tests/supervisor.rs` passes its command line to
`cmd.exe` with `raw_arg`. `Command::arg` escapes an embedded quote as `\"`, which
`cmd` does not parse that way, so a redirect to a quoted path silently never ran —
the attack did nothing, the file was unchanged, and reading it back looked like a
refusal. Every enforcement assertion would have passed against a Ralon that
enforced nothing. Caught because the tests also assert the control case: that the
same write *succeeds* before the policy is applied.

## 0.1.5

Enforcement is not the only thing that has to be legible. When Ralon refuses a
write, the message the developer or the agent actually reads is produced by
whatever attempted it — and `EBUSY: resource busy or locked` reads like a
corrupt file, not a policy. This release fixes the wording where Ralon owns it
and warns about it where Ralon does not.

### Changed

- **The hook now says "protected by Ralon"** rather than naming only the file
  it came from. This is the one refusal whose wording belongs to Ralon: without
  a hook the agent reports whatever its runtime made of the OS error — Node
  renders a Windows sharing violation as `EBUSY: resource busy or locked` —
  which reads as a broken file and sends the agent looking for a way around it
  rather than for something else to edit.
- **`init` and `guard --detach` say in advance what a refusal looks like**, in
  the spelling of the platform they are running on: `EBUSY` and `Access is
  denied` on Windows, `EPERM` on macOS, `EROFS` and `EACCES` on Linux. There is
  no interception point that would let Ralon rewrite those messages, so the
  honest move is to say once, before it happens, that the confusing error is
  the tool working.
- `init` closes with a link to the repository.

## 0.1.4

Ralon used to install cleanly on Windows and macOS, write a policy that looked
authoritative, confirm the paths were `locked`, and then enforce nothing —
while an agent edited those paths freely. Everything was behaving as designed
and documented, which is exactly what made it dangerous: the tool implied a
guarantee on platforms where it had none. This release closes that gap on
Windows with real enforcement, and everywhere else by saying so plainly.

### Added

- **macOS now enforces.** `agent.lock` is compiled to a Seatbelt profile and
  applied with `sandbox_init`, which is inherited across `exec` and by every
  descendant and cannot be left — the same shape as Linux, so `run` becomes the
  command and there is no supervisor to kill.

  It is the closest of the three platforms to the policy as written, because
  SBPL has `deny`. Nothing outside the named paths behaves differently (unlike
  Landlock, which must grant every sibling and leaves ancestors
  create-restricted), and a protected directory covers entries created inside
  it later (unlike the Windows locks, which need an ACL to reach that far).
  Ancestor directories are denied as nodes rather than subtrees, so they cannot
  be renamed away while their contents stay writable.

  The profile is generated by platform-independent code and unit-tested
  everywhere, and `run --dry-run --backend seatbelt` prints it on any machine —
  so what will be denied is reviewable without a Mac. The attack tables in
  `tests/enforcement.rs` now run against a real macOS kernel in CI with
  `RALON_REQUIRE_BACKEND=1`, which makes "nothing was tested" a failure.

  `sandbox_init` is deprecated and used anyway: it is what every sandboxed
  application on macOS uses, and the supported alternative is an entitlement on
  a signed `.app` bundle, which a CLI cannot be. `security.md` names it as a
  dependency rather than leaving it implied. A profile the kernel rejects is an
  error, never a warning — the command is not started.
- **Windows now enforces.** `ralon run` holds every protected file open with a
  share mode that allows readers and refuses writers, so writing, deleting,
  renaming or replacing one fails with a sharing violation — for **every
  process on the machine**, whichever agent it belongs to and whether or not
  that agent supports hooks. Verified against the same attack battery the Linux
  backends face: overwrite, append, delete, rename away, replace by copy or
  move, rename the parent directory, write inside a protected directory, remove
  the tree, rewrite the policy, and clear the read-only attribute first. All
  refused; ordinary edits elsewhere unaffected.

  ACLs were the obvious approach and are the wrong one: the agent runs as the
  same user, so any permission Ralon can set it can unset. A handle is not a
  permission.

  The protection lasts only as long as `run`, so the command is placed in a job
  object that dies with Ralon, closing the "kill the supervisor and keep
  writing" hole.
- **`ralon guard` — protection with no command to wrap.** `run` protects the
  agent it starts; a guard protects the ones it does not. It holds the same
  locks with nothing to supervise, and Windows refuses them to every process on
  the machine, so an agent launched from an IDE, an extension, another
  terminal, or installed next month is refused without knowing Ralon exists.
  `--detach` to leave one running, `--stop` to hand the files back, and
  `status` says which. Verified against unwrapped `cmd.exe`: overwrite, append,
  delete, rename, writing a protected file, rewriting the policy, and creating
  a new file in a protected directory — all refused, with no `ralon run`
  anywhere.

  This is possible on Windows precisely because its locks are *held* rather
  than inherited, and impossible on Linux for the same reason in reverse: a
  Landlock domain is applied to a process before it runs and cannot be imposed
  on one you did not start. `ralon guard` on Linux says that instead of
  pretending.
- **New files inside a protected directory are refused.** The gap the handles
  could not reach — creating an entry opens no existing object, so no share
  mode applies — is closed with a deny ACE, covering create, `mkdir`, copying
  or moving a file in, and renaming one inside. It is a *narrowing*, not a
  guarantee, and `security.md` is explicit about why: the agent owns the
  directory and an owner's `WRITE_DAC` cannot be denied, tested. Every ordinary
  create is refused; an agent that rewrites the ACL gets its write.

  The ACE is removed on exit. If Ralon is killed it stays, which fails closed;
  `status` reports it and `ralon guard --stop` clears it.
- `ralon init` now installs the agent hooks as well as writing the policy
  (`--no-hooks` to skip), and points at the one command that protects the
  project rather than leaving the reader to find it.
- **`ralon hook install`** — wires a refusal into an agent's own configuration
  instead of leaving each user to hand-write JSON. **Nine agents**, all by
  default, `--agent` to pick one: Claude Code, GitHub Copilot, OpenAI Codex,
  Cursor, Gemini CLI, Google Antigravity, Cline, Windsurf/Cascade and OpenCode.
  Existing settings and unrelated hooks are preserved; a settings file that
  cannot be parsed is never touched.
- `ralon hook check` makes the decision for all nine: one JSON document
  carrying every key they read — `permissionDecision`, `decision`/`reason`,
  `permission`/`agent_message`, `cancel`/`errorMessage` — plus exit code 2.
  Emitting a key an agent ignores costs nothing; omitting one it needs is an
  edit waved through.
- Paths are found under any spelling, at any depth, compared after lowercasing
  and dropping underscores — `file_path`, `filePath`, `TargetFile`,
  `AbsolutePath` are one entry, not four. Agents nest differently too, so
  Antigravity's `{"toolCall": {"name", "args"}}` is understood as well.
- **Reads are never refused.** Some agents call the hook for *every* tool
  rather than only for edits, so the check recognises a read and allows it.
  Without that, an agent would be refused permission to look at the very policy
  governing it. A tool name that is not recognisably a read is treated as a
  write, because the two mistakes are not equal.
- **JetBrains Junie and Roo Code are deliberately not installed.** Junie
  ignores project-local hooks by default, so the file would silently do
  nothing; Roo Code has no hook API yet, and its `.rooignore` blocks reads as
  well as writes. Both are covered by `run` and `guard` like everything else.
- None of this is needed where enforcement is running: `run` and `guard`
  restrict the *process*, so they already cover Aider, Amazon Q, Junie, Roo
  Code and anything shipped next year, hooks or no hooks.
- **An audit that runs before the agent does.** `status` and `run` now report
  conditions that weaken a policy without breaking it — and, on Windows, one
  that means the policy is naming the wrong thing: a protected file another
  program already holds open, such as a live database or a log a dev server
  appends to. It cannot be locked, so `status` warns and `run` refuses to start
  rather than reporting it as protected while it is not.

### Security

- **A pre-existing hard link to a protected file bypasses both backends.** The
  other name is an ordinary file: not bind-mounted, not carved out of the
  Landlock grant, and writing it changes the protected file. Verified against a
  live kernel — a write through the second name changed `.env` inside the
  sandbox. Ralon now warns when a protected file has more than one link. This
  was previously undocumented.
- **A second mount of the project bypasses both backends**, which
  `security.md` already documented. Ralon now detects it by reading
  `/proc/self/mountinfo` and names the other path.
- `run` and `status` no longer report "unavailable" and stop there. They say
  plainly that nothing is protecting those paths, and what to do instead.

### Changed

- Enforcement is split one directory per platform — `enforce/linux/{mount,
  landlock,sys}`, `enforce/windows/{locks,acl,job,guard}`,
  `enforce/macos/seatbelt`, `enforce/other` — with planning left
  platform-independent so `--dry-run` shows the same plan everywhere, and now
  the same Seatbelt profile too.
- **`rust-version` is 1.88, and true.** It said 1.79, which had not been
  buildable for some time: `clap_lex` requires edition 2024 and `globset`
  requires 1.88, so an older toolchain failed with a dependency's error instead
  of a clear message about this crate. Checked against 1.79, 1.85 and 1.88.
- `enforce_and_exec` returns the command's exit status instead of only an
  error. Linux still replaces the process and never returns; Windows has no
  inheritable restriction to hand over, so it supervises and reports back.
- The hook is one file per agent (`hook/{claude,copilot,codex,cursor,gemini,
  antigravity,windsurf,cline,opencode}.rs`), so supporting another is a new
  file rather than an edit to the policy logic. The three that share a
  settings-file shape share one installer rather than three copies drifting
  apart.

## 0.1.3

### Fixed

- **`npm install ralonlock` was unusable in 0.1.2**: every invocation failed
  with `EACCES`. GitHub Actions artifacts do not preserve file permissions, so
  the npm job packed a binary with the executable bit already stripped. The
  packager now sets it explicitly, and the shim repairs an install that has the
  problem instead of failing. Only npm was affected — the release archives are
  built where the binary is compiled, and the wheels set the mode themselves.
- `dist/` and `artifacts/` are ignored by git and excluded from the crate
  tarball. Packager output had been committed, and would have shipped to
  `cargo install` users.

## 0.1.2

The first release to reach npm and PyPI. No change to what Ralon does: `0.1.1`
published to crates.io, but the npm and PyPI configuration could only be fixed
by releasing again, because the packaging scripts are read from the tag.

- `npm install -g ralonlock` — the binaries wrapped as `ralonlock`, plus five
  `@stoneware-dev/<platform>` packages so npm downloads only the one that
  matches. Neither `ralon` nor `@ralon` was available: npm refuses the first as
  too similar to the existing `raven`, and the second scope was taken.
- `pip install ralonlock` / `uv tool install ralonlock` — the same binaries as
  wheels.
- The command is `ralon` however it was installed. Only the crate kept the
  name.
- Release workflow actions moved to their Node 24 versions, and the npm step
  skips versions that are already published, so a partial failure can be
  re-run instead of costing a version.

## 0.1.1

Published to crates.io, with prebuilt binaries on the GitHub release. No change
to what Ralon does or to what a policy means; this is the first release built
and published by CI from a tagged commit.

### Distribution

- Prebuilt binaries for five targets, attached to the GitHub release with
  SHA-256 checksums. Linux builds are static musl, so they run anywhere,
  including containers with no glibc. `cargo binstall ralon` works.
- A tag publishes to all three registries after one manual approval.

### Packaging

- The crate tarball no longer carries the release plumbing (`npm/`,
  `packaging/`, workflows). Crate users still get `README.md`,
  `architecture.md`, `security.md`, `LICENSE` and the tests.

### Fixed

- The musl targets did not compile: `libc::ST_*` is defined only for glibc, so
  the flags read back before a read-only remount are now spelled out from the
  kernel's own values. No effect on behaviour — glibc builds were identical —
  but without it there are no static Linux binaries. CI now compiles the musl
  target on every push.

## 0.1.0

First release. Published by hand from a working tree with uncommitted changes,
so it corresponds to no commit in the repository; `0.1.1` is identical in
behaviour and reproducible.

### Added

- `agent.lock`: a YAML policy declaring paths AI agents may not modify.
  `agent.lock` protects itself. Patterns are relative to it; `..`, absolute
  paths, `~` and `!` are rejected rather than reinterpreted.
- `ralon run -- <command>` restricts the current process and `exec`s the
  command, so the restriction is inherited by every descendant and cannot be
  dropped. Two Linux backends:
  - **mount** (default) — read-only bind mounts in a user + mount namespace,
    locked by entering a second namespace. Ancestor directories are pinned as
    mount points, so none can be renamed out from under a protected path.
  - **landlock** — the LSM, for hosts without user namespaces. Landlock rules
    are additive, so "everything except this file" is expressed by granting
    every sibling along the way; the cost is that directories leading to a
    protected path accept no new entries.
- `ralon init`, `check`, `status`, and `run --dry-run`. `check` exits 1 for a
  protected path, which is enough to drive an agent's pre-write hook.
- `init`, `check` and `status` work on Windows and macOS; only `run` needs
  Linux.

### Security

- Enforcement is verified by `tests/enforcement.rs`, which attempts real
  bypasses — overwrite, append, truncate, delete, rename away, rename over,
  delete-and-recreate, hard link, symlink, chmod-then-write, parent rename,
  `umount`, bind-mount-around, nested namespaces — against a live sandbox, for
  every backend the kernel provides.
- Known limitations are documented in `security.md`. The one to know: both
  backends are path-based, so a second pre-existing mount of the same directory
  is not covered.
- If no backend is available, `run` refuses to start the command rather than
  running it unprotected.
