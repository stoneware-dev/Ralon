//! End-to-end tests for the parts of the CLI that work on every platform.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ralon");

/// A throwaway project directory, removed on drop.
struct Project {
    root: PathBuf,
}

impl Project {
    fn new(policy: Option<&str>) -> Project {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "ralon-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(unique);
        fs::create_dir_all(&root).unwrap();

        let project = Project { root };
        if let Some(policy) = policy {
            project.write("agent.lock", policy);
        }
        project
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(arguments)
            // `run` hands the command the working directory it was given, so a
            // test that leaves this at the harness's cwd is testing the repo,
            // not the project — which is how the first version of the Windows
            // test passed while protecting nothing.
            .current_dir(&self.root)
            .output()
            .expect("failed to run ralon")
    }

    /// A command run *outside* Ralon, the way an agent someone launched from
    /// an IDE is outside it.
    #[cfg(windows)]
    fn shell(&self, command: &str) {
        Command::new("cmd")
            .args(["/c", command])
            .current_dir(&self.root)
            .output()
            .expect("failed to run cmd");
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
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

const POLICY: &str = "version: 1\nprotect:\n  - src/index.tsx\n  - .env\n  - config/**\n";

#[test]
fn init_writes_a_usable_policy_and_refuses_to_clobber_it() {
    let project = Project::new(None);

    let created = project.run(&["init"]);
    assert_eq!(code(&created), 0, "{}", stderr(&created));
    assert!(project.root.join("agent.lock").is_file());

    let again = project.run(&["init"]);
    assert_eq!(code(&again), 2);
    assert!(
        stderr(&again).contains("already exists"),
        "{}",
        stderr(&again)
    );

    // The generated file must be valid input for the tool itself.
    let status = project.run(&["status"]);
    assert_eq!(code(&status), 0, "{}", stderr(&status));
}

#[test]
fn check_reports_protected_paths_and_exits_nonzero() {
    let project = Project::new(Some(POLICY));

    let protected = project.run(&["check", "src/index.tsx"]);
    assert_eq!(code(&protected), 1);
    assert!(
        stdout(&protected).contains("locked"),
        "{}",
        stdout(&protected)
    );

    let writable = project.run(&["check", "src/App.tsx"]);
    assert_eq!(code(&writable), 0);
    assert!(stdout(&writable).contains("writable"));
}

#[test]
fn check_protects_the_policy_file_itself() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "agent.lock"]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
}

#[test]
fn check_covers_paths_inside_a_protected_directory() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "config/deep/db.yaml", "src/App.tsx"]);
    assert_eq!(code(&output), 1);
    let text = stdout(&output);
    assert!(text.contains("locked    config/deep/db.yaml"), "{text}");
    assert!(text.contains("writable  src/App.tsx"), "{text}");
}

#[test]
fn check_notices_paths_outside_the_project() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "../elsewhere.txt"]);
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains("outside"), "{}", stdout(&output));
}

#[test]
fn check_without_arguments_lists_what_exists() {
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");
    project.write("src/App.tsx", "writable\n");
    project.write("config/db.yaml", "locked\n");

    let output = project.run(&["check"]);
    let text = stdout(&output);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(text.contains("agent.lock"), "{text}");
    assert!(text.contains("src/index.tsx"), "{text}");
    // A protected directory is listed once, not expanded entry by entry.
    assert!(text.contains("config/"), "{text}");
    assert!(!text.contains("config/db.yaml"), "{text}");
    assert!(!text.contains("App.tsx"), "{text}");
    // `.env` is declared but absent, so there is nothing to lock.
    assert!(
        stderr(&output).contains("`.env` matches nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn commands_find_the_policy_from_a_subdirectory() {
    let project = Project::new(Some(POLICY));
    project.write("src/deep/nested.txt", "x\n");

    let output = Command::new(BINARY)
        .arg("--dir")
        .arg(project.root.join("src").join("deep"))
        .args(["check", "../index.tsx"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
}

#[test]
fn missing_policy_is_an_error_not_a_silent_pass() {
    let project = Project::new(None);
    let output = project.run(&["check", "anything.txt"]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("no agent.lock"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_broken_policy_stops_everything() {
    let project = Project::new(Some("version: 1\nprotect:\n  - ../escape\n"));
    let output = project.run(&["check", "src/App.tsx"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains(".."), "{}", stderr(&output));
}

#[test]
fn dry_run_describes_what_would_be_locked() {
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");
    project.write("config/db.yaml", "locked\n");

    let output = project.run(&["run", "--dry-run", "--", "echo", "hello"]);
    let text = stdout(&output);
    assert!(text.contains("read-only  src/index.tsx"), "{text}");
    assert!(text.contains("read-only  config/"), "{text}");
    assert!(text.contains("read-only  agent.lock"), "{text}");
    assert!(text.contains("echo hello"), "{text}");

    // The plan is always shown. Whether it could be enforced depends on the
    // kernel, and the tool must say which instead of pretending either way.
    match code(&output) {
        0 => assert!(!text.contains("would fail"), "{text}"),
        1 => assert!(text.contains("would fail"), "{text}"),
        other => panic!("unexpected exit code {other}\n{text}\n{}", stderr(&output)),
    }
}

#[test]
fn status_lists_backends() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["status"]);
    let text = stdout(&output);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(text.contains("backends"), "{text}");
    assert!(text.contains("mount"), "{text}");
    assert!(text.contains("landlock"), "{text}");
    assert!(text.contains("version    1"), "{text}");
}

/// Windows enforcement, for real: the protected file is held open, so anything
/// that tries to write it gets a sharing violation. This is the counterpart of
/// `tests/enforcement.rs`, which can only run on Linux.
#[test]
#[cfg(windows)]
fn windows_locks_stop_a_write_from_any_process() {
    let project = Project::new(Some(POLICY));
    let secret = project.write(".env", "SECRET=original\n");
    project.write("src/App.tsx", "writable\n");

    // cmd.exe is not an agent and has never heard of a policy — which is the
    // point. The backend blocks processes, not tools that opted in.
    let blocked = project.run(&["run", "--quiet", "--", "cmd", "/c", "echo hacked > .env"]);
    assert_ne!(code(&blocked), 0, "the write should have failed");
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        "SECRET=original\n",
        "a protected file was modified"
    );

    // Deleting needs FILE_SHARE_DELETE, which the lock does not grant. `del`
    // reports success even when it failed, so the file on disk is the only
    // thing worth asserting on.
    project.run(&["run", "--quiet", "--", "cmd", "/c", "del /q .env"]);
    assert!(secret.is_file(), "a protected file was deleted");
    assert_eq!(fs::read_to_string(&secret).unwrap(), "SECRET=original\n");

    // Renaming it away is the same operation to Windows, and equally refused.
    project.run(&["run", "--quiet", "--", "cmd", "/c", "ren .env moved.txt"]);
    assert!(secret.is_file(), "a protected file was renamed away");

    // And ordinary work still goes through, or the backend is useless.
    let allowed = project.run(&[
        "run",
        "--quiet",
        "--",
        "cmd",
        "/c",
        "echo edited > src\\App.tsx",
    ]);
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    assert!(fs::read_to_string(project.root.join("src/App.tsx"))
        .unwrap()
        .contains("edited"));
}

/// The gap a handle cannot reach: creating a *new* entry inside a protected
/// directory opens no existing object, so no share mode is consulted. A deny
/// ACE covers it, and has to come off again afterwards.
#[test]
#[cfg(windows)]
fn windows_refuses_new_files_in_a_protected_directory() {
    let project = Project::new(Some(POLICY));
    project.write("config/db.yaml", "locked\n");

    for attack in [
        "echo hacked > config\\new.yaml",
        "mkdir config\\sneaky",
        "echo hacked > config\\nested\\deep.yaml",
    ] {
        project.run(&["run", "--quiet", "--", "cmd", "/c", attack]);
    }

    assert!(
        !project.root.join("config/new.yaml").exists(),
        "a new file appeared inside a protected directory"
    );
    assert!(!project.root.join("config/sneaky").exists());
    assert!(!project.root.join("config/nested").exists());

    // Renaming an existing entry needs the same right, so it goes too.
    project.run(&[
        "run",
        "--quiet",
        "--",
        "cmd",
        "/c",
        "ren config\\db.yaml x.yaml",
    ]);
    assert!(project.root.join("config/db.yaml").is_file());

    // And the directory is an ordinary directory again once nothing is
    // running. Leaving a permission behind would be worse than the gap.
    fs::write(project.root.join("config/after.yaml"), "fine")
        .expect("the ACL should have been restored when the command finished");
}

/// A file something else is using is the wrong thing to protect — a live
/// database, a log a dev server appends to. Ralon cannot lock it, and finding
/// that out when `run` fails is worse than being told beforehand.
#[test]
#[cfg(windows)]
fn a_file_already_in_use_is_reported_before_it_becomes_a_failure() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    let project = Project::new(Some("version: 1\nprotect:\n  - app.db\n"));
    let database = project.write("app.db", "rows\n");

    let quiet = stderr(&project.run(&["status"]));
    assert!(!quiet.contains("app.db is held open"), "{quiet}");

    // Opened for writing and shared only for reading: what a running database
    // does, and what makes the lock impossible to take.
    let holder = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(&database)
        .unwrap();

    let warned = stderr(&project.run(&["status"]));
    assert!(warned.contains("app.db is held open"), "{warned}");

    // And it refuses to run rather than reporting a path as locked when it is
    // not. A failure to enforce is never silent.
    let refused = project.run(&["run", "--quiet", "--", "cmd.exe", "/c", "ver"]);
    assert_eq!(code(&refused), 2, "{}", stderr(&refused));

    drop(holder);
    let quiet_again = stderr(&project.run(&["status"]));
    assert!(
        !quiet_again.contains("app.db is held open"),
        "{quiet_again}"
    );
}

/// The guard: protection with no command to wrap, which is the only way to
/// cover an agent started from an IDE, an extension, or another terminal.
#[test]
#[cfg(windows)]
fn windows_guard_protects_a_process_it_did_not_start() {
    let project = Project::new(Some(POLICY));
    let secret = project.write(".env", "SECRET=original\n");
    project.write("src/App.tsx", "writable\n");

    // Nothing is guarding yet, so this must succeed — otherwise the assertion
    // below proves nothing.
    project.shell("echo unguarded > .env");
    assert!(fs::read_to_string(&secret).unwrap().contains("unguarded"));
    fs::write(&secret, "SECRET=original\n").unwrap();

    let started = project.run(&["guard", "--detach"]);
    assert_eq!(code(&started), 0, "{}", stderr(&started));

    let status = stdout(&project.run(&["status"]));
    assert!(status.contains("guard      running"), "{status}");

    // No `ralon run` anywhere: an ordinary process, started the ordinary way.
    project.shell("echo hacked > .env");
    project.shell("del /q .env");
    project.shell("echo x > config\\new.yaml");
    let held = fs::read_to_string(&secret).unwrap() == "SECRET=original\n"
        && !project.root.join("config/new.yaml").exists();

    // Released before asserting, so a failure does not leave a guard holding
    // the directory this test is about to delete.
    let stopped = project.run(&["guard", "--stop"]);
    assert!(held, "a guarded path was modified by an unwrapped process");
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));

    project.shell("echo released > .env");
    assert!(fs::read_to_string(&secret).unwrap().contains("released"));
}

/// A failure to enforce is never silent, and never partial: if the requested
/// backend cannot be applied, the command does not start at all.
///
/// This used to run only where *no* backend existed, which meant it stopped
/// testing anything the moment macOS gained one — and it failed by trying to
/// launch a Windows shell on a Mac. Asking for a backend that cannot exist on
/// this platform tests the same refusal, and every platform has one of those.
#[test]
fn run_refuses_rather_than_running_unprotected_when_the_backend_is_unavailable() {
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");

    // `locks` is a Windows idea; `mount` is a Linux one. Neither exists on the
    // other platforms, and `resolve` has to say so rather than panicking on a
    // backend its own table does not list.
    let elsewhere = if cfg!(target_os = "linux") {
        "locks"
    } else {
        "mount"
    };

    let marker = project.root.join("should-not-exist.txt");
    let (shell, flag, script) = if cfg!(windows) {
        ("cmd", "/c", format!("type nul > {}", marker.display()))
    } else {
        ("sh", "-c", format!("touch '{}'", marker.display()))
    };

    let output = project.run(&["run", "--backend", elsewhere, "--", shell, flag, &script]);

    assert_eq!(code(&output), 2, "{}", stdout(&output));
    // The refusal has to say what is missing, or the reader concludes the
    // policy is protecting them when nothing is.
    let explanation = stderr(&output);
    assert!(explanation.contains("unavailable"), "{explanation}");
    assert!(!marker.exists(), "the command must not have run");
}

#[test]
fn hook_install_writes_a_hook_that_refuses_protected_paths() {
    let project = Project::new(Some(POLICY));

    // `--agent claude` because this test is about Claude's file specifically; the
    // bare default is `auto`, which writes only the agents the machine uses and
    // would make the assertion depend on what is installed on it.
    let installed = project.run(&["hook", "install", "--agent", "claude"]);
    assert_eq!(code(&installed), 0, "{}", stderr(&installed));

    let settings = fs::read_to_string(project.root.join(".claude/settings.json")).unwrap();
    assert!(settings.contains("ralon hook check"), "{settings}");
    assert!(settings.contains("PreToolUse"), "{settings}");
    // Bash is deliberately not matched: a hook cannot tell which paths a shell
    // command touches, and claiming otherwise would be worse than the gap.
    assert!(!settings.contains("Bash"), "{settings}");
}

#[test]
fn the_installed_hook_denies_and_allows_the_right_paths() {
    let project = Project::new(Some(POLICY));

    for (relative, expected_deny) in [(".env", true), ("src/App.tsx", false)] {
        let request = format!(
            r#"{{"tool_name":"Write","tool_input":{{"file_path":{}}}}}"#,
            serde_json_string(&project.root.join(relative).to_string_lossy()),
        );

        let mut child = Command::new(BINARY)
            .arg("--dir")
            .arg(&project.root)
            .args(["hook", "check"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();

        let text = stdout(&output);
        // Exit 2 is what every supported agent reads as "blocked". The JSON
        // carries the reason for the ones that show it to the model, and it
        // carries both spellings — Claude reads one, Cursor the other.
        assert_eq!(
            code(&output),
            if expected_deny { 2 } else { 0 },
            "{relative}: {text}{}",
            stderr(&output)
        );
        assert_eq!(
            text.contains("\"permission\":\"deny\""),
            expected_deny,
            "Cursor's key is missing: {text}"
        );
        assert_eq!(
            text.contains("\"permissionDecision\":\"deny\""),
            expected_deny,
            "{relative} produced: {text}"
        );
    }
}

/// An installed hook that cannot run, which is worse than no hook at all.
///
/// Every hook entry invokes `ralon hook check` by name, because those files get
/// committed and an absolute path would be one machine's home directory in
/// everybody's repository. So if the name does not resolve, the shell exits 1 —
/// and 1 is not the code any agent reads as "deny". The edit goes ahead, the
/// kernel refuses it, and the developer is handed `EBUSY: resource busy or
/// locked` about a repository that is working exactly as intended.
///
/// Nothing reported that state until this. It is reachable by ordinary means:
/// `ralon install` stages its own copy of the binary so the package can be
/// uninstalled, and uninstalling the package is what takes `ralon` off PATH.
#[test]
fn status_reports_a_hook_that_is_installed_but_cannot_run() {
    let project = Project::new(Some(POLICY));
    let home = project.root.join("state");
    fs::create_dir_all(&home).unwrap();

    let installed = project.run(&["hook", "install"]);
    assert_eq!(code(&installed), 0, "{}", stderr(&installed));

    let status = |path: &std::path::Path| -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&project.root)
            .arg("status")
            .env("RALON_HOME", &home)
            .env("PATH", path)
            .current_dir(&project.root)
            .output()
            .expect("failed to run ralon")
    };

    // Both streams: the explanation is advisory output like the rest of what
    // `status` prints, and asserting on one stream would make this test pass or
    // fail on where a message happens to be sent rather than on whether it is
    // there at all.
    let said = |output: &Output| format!("{}{}", stdout(output), stderr(output));

    let nowhere = project.root.join("nowhere");
    fs::create_dir_all(&nowhere).unwrap();
    let reported = said(&status(&nowhere));
    assert!(
        reported.contains("not on PATH"),
        "a hook that cannot run was not reported: {reported}"
    );
    // And it says what to do about it, rather than only that something is wrong.
    assert!(
        reported.contains("https://github.com/stoneware-dev/Ralon"),
        "the explanation does not point anywhere: {reported}"
    );

    // The control, and the only reason the assertion above proves anything: the
    // same project, with a PATH that does contain a `ralon`, must say nothing.
    // Without this a version that warned unconditionally would pass.
    let beside_the_binary = std::path::Path::new(BINARY)
        .parent()
        .expect("the test binary has a directory");
    let reported = said(&status(beside_the_binary));
    assert!(
        !reported.contains("not on PATH"),
        "warned about a `ralon` that is on PATH: {reported}"
    );
}

/// Runs one hook request and returns (exit code, stdout).
fn hook(project: &Project, request: &str) -> (i32, String) {
    let mut child = Command::new(BINARY)
        .arg("--dir")
        .arg(&project.root)
        .args(["hook", "check"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (code(&output), stdout(&output))
}

fn write_request(paths: &[std::path::PathBuf]) -> String {
    let edits: Vec<String> = paths
        .iter()
        .map(|path| {
            format!(
                r#"{{"file_path":{}}}"#,
                serde_json_string(&path.to_string_lossy())
            )
        })
        .collect();
    format!(
        r#"{{"tool_name":"MultiEdit","tool_input":{{"edits":[{}]}}}}"#,
        edits.join(",")
    )
}

/// A denied edit is a denied *edit* — not a denied session.
///
/// The failure this guards against is the one that makes a policy tool
/// unusable: an agent asked to touch three files, one of them protected, and the
/// whole run ends. Ralon refuses the tool call and nothing else — it does not
/// stop the agent, does not release the guard, and does not stop enforcing. The
/// agent is expected to carry on with the work it is allowed to do, so the test
/// carries on the same way and checks that it can.
#[test]
fn a_denial_refuses_the_operation_and_nothing_else() {
    let project = Project::new(Some(POLICY));
    let secret = project.write(".env", "SECRET=original\n");
    let allowed = project.write("src/App.tsx", "original\n");

    // 1. An allowed file, on its own: permitted.
    let (allowed_first, _) = hook(&project, &write_request(std::slice::from_ref(&allowed)));
    assert_eq!(allowed_first, 0, "an unprotected file was refused");

    // 2. A protected file: refused, and every protected path in the request is
    //    named so the agent can fix it in one attempt.
    let mixed = write_request(&[
        allowed.clone(),
        secret.clone(),
        project.root.join("config/db.yaml"),
    ]);
    let (denied, said) = hook(&project, &mixed);
    assert_eq!(denied, 2, "a protected path was not refused: {said}");
    assert!(said.contains(".env"), "{said}");
    assert!(
        said.contains("config/db.yaml"),
        "only the first protected path was named: {said}"
    );
    assert!(
        said.contains("nothing in it was modified"),
        "the refusal does not say the allowed paths were left alone: {said}"
    );

    // 3. Nothing was written — not the protected file, and not the allowed one
    //    that shared the refused call. Read back, never inferred from an exit
    //    code, because that is the claim the message makes to the agent.
    assert_eq!(fs::read_to_string(&secret).unwrap(), "SECRET=original\n");
    assert_eq!(fs::read_to_string(&allowed).unwrap(), "original\n");

    // 4. The agent continues. The same allowed edit, after the denial, is still
    //    permitted — the denial did not poison the session, and the hook process
    //    exiting 2 was an answer about one call rather than a failure.
    let (allowed_after, _) = hook(&project, &write_request(std::slice::from_ref(&allowed)));
    assert_eq!(
        allowed_after, 0,
        "an allowed edit was refused after an unrelated denial"
    );

    // 5. And the policy is still being enforced afterwards, rather than having
    //    been spent on the refusal.
    let (still_denied, _) = hook(&project, &write_request(&[secret]));
    assert_eq!(
        still_denied, 2,
        "the protected path stopped being protected"
    );
}

/// The same sequence with real enforcement underneath it: a hook denial must not
/// disturb the guard holding the files.
#[test]
#[cfg(windows)]
fn a_denial_leaves_the_guard_running_and_enforcing() {
    let project = Project::new(Some(POLICY));
    let secret = project.write(".env", "SECRET=original\n");

    let started = project.run(&["guard", "--detach"]);
    assert_eq!(code(&started), 0, "{}", stderr(&started));

    let (denied, _) = hook(&project, &write_request(std::slice::from_ref(&secret)));

    // The guard is still there, and still refusing an unwrapped process — the
    // filesystem half is untouched by anything the hook decided.
    let status = stdout(&project.run(&["status"]));
    project.shell("echo hacked > .env");
    let held = fs::read_to_string(&secret).unwrap() == "SECRET=original\n";

    let stopped = project.run(&["guard", "--stop"]);
    assert_eq!(denied, 2, "the hook allowed a protected write");
    assert!(
        status.contains("guard      running"),
        "the guard stopped after a hook denial: {status}"
    );
    assert!(held, "enforcement lapsed after a hook denial");
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
}

/// Minimal JSON string escaping, so the test needs no dependency.
fn serde_json_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[test]
fn the_binary_reports_a_version() {
    let output = Command::new(BINARY).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}
