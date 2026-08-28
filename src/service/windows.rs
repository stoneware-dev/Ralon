//! A Task Scheduler logon task, registered from XML.
//!
//! `schtasks /Create /SC ONLOGON` on the command line would be three lines
//! instead of this file, and it would ship a bug: a task created that way gets
//! the default `ExecutionTimeLimit` of `PT72H`, so Windows would terminate the
//! supervisor after three days and every protected workspace would quietly
//! become writable. There is no command-line switch to change it. `/XML` is the
//! only way to say `PT0S`.
//!
//! Per-user and unelevated: the task runs as the user who installed it, with
//! `LeastPrivilege`. Nothing here needs administrator, and a Ralon that asked
//! for it would be handing an agent something better to attack than the files
//! it is guarding.
//!
//! # The console window
//!
//! `ralon` is a console program, and a console program started by something
//! without a console of its own gets a fresh one — visible, in the middle of the
//! screen. Task Scheduler is such a thing, so registering the supervisor used to
//! mean a black window at `ralon install` and another at every logon after it.
//!
//! `<Hidden>` does not fix this and this file used to claim it did. `Hidden`
//! controls whether the task is listed in the Task Scheduler UI; it has nothing
//! to say about windows the task's process opens. Neither does `CREATE_NO_WINDOW`
//! — that is a creation flag, and Task Scheduler does not offer one.
//!
//! `<LogonType>S4U</LogonType>` does fix it, by running the task in session 0,
//! where there is no desktop for a console to appear on. It needs no password
//! and no administrator. The cost is that a session-0 process has no network
//! credentials, so a scope on a mapped drive or a UNC path is unreachable from
//! it — [`super::network_scope_warning`] is why that is said out loud rather
//! than discovered.
//!
//! Enforcement itself is unaffected, and that is worth stating because it is the
//! part that would matter if it were wrong: the Windows backend works by holding
//! file handles, and a handle is a kernel object with no session in it. Verified
//! rather than assumed — a supervisor in session 0 was watched starting a guard
//! for a new `agent.lock`, and writes, deletes and renames from an interactive
//! session were all refused with the file's contents unchanged afterwards.
//!
//! Not every machine allows S4U: it needs the batch logon right, which a locked
//! down domain policy can withhold. Registration therefore tries S4U and falls
//! back to `InteractiveToken`, which always works and shows the window — with a
//! warning saying so, because a silently reappearing window would send the next
//! person back to this same investigation.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::{pathvar, Registration};

pub const SUPPORTED: bool = true;

/// Windows is the only platform where Ralon edits `PATH` for you. See
/// [`super::pathvar`] for why the others are told rather than changed.
pub const CAN_EDIT_PATH: bool = true;

/// Shown in Task Scheduler, and the handle for `/Delete`.
const TASK: &str = "Ralon Supervisor";

/// `CREATE_NO_WINDOW`.
///
/// `schtasks` is a console program, and a console program inherits its parent's
/// console — *unless the parent has not got one*, in which case Windows gives it
/// a fresh one, visible, in the middle of the screen. Every caller here happens
/// to run from a terminal today, so this changes nothing today; it stops a
/// window appearing the first time one of them is called from the supervisor, a
/// service, or anything else without a console of its own. The output is
/// captured either way.
const NO_WINDOW: u32 = 0x0800_0000;

/// `schtasks` with the arguments given, and no window under any circumstances.
fn schtasks(arguments: &[&str]) -> Command {
    let mut command = Command::new("schtasks");
    command.args(arguments).creation_flags(NO_WINDOW);
    command
}

pub fn install(executable: &Path, home: &Path) -> Result<Registration> {
    let user = account();
    let mut warnings = Vec::new();

    // S4U first, because it is the one that does not open a console window.
    // Falling back rather than failing: a machine whose policy withholds the
    // batch logon right should still get a supervisor, and be told what it cost.
    let mut created = register(executable, home, &user, LogonType::S4U)?;
    if !created.status.success() {
        let reason = message(&created);
        created = register(executable, home, &user, LogonType::Interactive)?;
        if created.status.success() {
            warnings.push(format!(
                "this machine would not accept a background (S4U) task ({reason}), so the \
                 supervisor runs interactively and a console window will appear at each \
                 logon. Enforcement is unaffected"
            ));
        }
    }

    if !created.status.success() {
        anyhow::bail!(
            "schtasks refused to register the supervisor: {}",
            message(&created)
        );
    }

    // Any old instance is already gone: `commands::install` calls
    // [`stop`] and then waits for the claim to be released, because it has to
    // replace the binary that instance was running from. Worth stating because
    // `MultipleInstancesPolicy` is `IgnoreNew` — `/Run` against a task that is
    // still running does nothing whatsoever and reports success, which is how a
    // re-install used to leave the *previous* binary supervising until the next
    // logon while `ralon --version` reported the new one.

    // Registered is not running: the trigger is the *next* logon, and a
    // developer who just ran `ralon install` is owed enforcement now rather
    // than after a reboot.
    let started = schtasks(&["/Run", "/TN", TASK])
        .output()
        .context("failed to run schtasks")?;
    if !started.status.success() {
        warnings.push(format!(
            "the task is registered but would not start now ({}) — it will start at \
             the next logon, or run `ralon daemon` in a terminal to see why",
            message(&started)
        ));
    }

    Ok(Registration {
        mechanism: "a Task Scheduler logon task",
        path: None,
        warnings,
    })
}

/// Ends the running instance without deregistering it.
///
/// Called before `install` replaces the staged binary. A running supervisor
/// holds that file exclusively (see `supervisor::selfguard`), which is the whole
/// point of it — but it means an upgrade has to ask the old one to let go first,
/// rather than discovering it cannot write the file and giving up.
pub fn stop() {
    let _ = schtasks(&["/End", "/TN", TASK]).output();
}

/// Starts the registered task, if there is one.
pub fn start() -> Result<()> {
    if !installed() {
        return Ok(());
    }
    let started = schtasks(&["/Run", "/TN", TASK])
        .output()
        .context("failed to run schtasks")?;
    if !started.status.success() {
        anyhow::bail!("{}", message(&started));
    }
    Ok(())
}

pub fn uninstall() -> Result<bool> {
    if !installed() {
        return Ok(false);
    }
    // Ends the running instance first. Deleting a task does not stop it, and a
    // supervisor left running with no registration is the one state nothing
    // would ever report.
    let _ = schtasks(&["/End", "/TN", TASK]).output();

    let removed = schtasks(&["/Delete", "/TN", TASK, "/F"])
        .output()
        .context("failed to run schtasks")?;
    if !removed.status.success() {
        anyhow::bail!(
            "schtasks would not remove the supervisor task: {}",
            message(&removed)
        );
    }
    Ok(true)
}

pub fn installed() -> bool {
    // Called by `ralon status`, which an agent runs through its shell often
    // enough that a window here would be noticed.
    schtasks(&["/Query", "/TN", TASK])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// The executable the registration currently points at.
///
/// `status` uses this to catch a registration whose binary has been deleted —
/// the state a machine ends up in when Ralon was installed from a package
/// manager and then removed with that package manager. Task Scheduler keeps the
/// entry, tries it at every logon, fails, and reports nothing anybody reads.
pub fn registered_path() -> Option<PathBuf> {
    let output = schtasks(&["/Query", "/TN", TASK, "/XML", "ONE"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // `schtasks /XML` writes UTF-16LE. Decoding it properly matters for a path
    // with a non-ASCII character in it, which is most paths under a home
    // directory named for a person.
    let xml = decode(&output.stdout);
    let start = xml.find("<Command>")? + "<Command>".len();
    let end = xml[start..].find("</Command>")? + start;
    Some(PathBuf::from(unescape(xml[start..end].trim())))
}

pub fn unsupported_reason() -> String {
    String::new()
}

/// `DOMAIN\user`, which both the trigger and the principal have to name.
///
/// Falls back to the machine name, which is what `USERDOMAIN` holds on a
/// machine that has never been joined to anything.
fn account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    }
}

/// How the task's process gets its token, which decides whether it has a
/// desktop to open a window on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LogonType {
    /// Session 0. No console window is possible, and no network credentials.
    S4U,
    /// The user's own session. Always available, always shows the window.
    Interactive,
}

impl LogonType {
    fn xml(self) -> &'static str {
        match self {
            LogonType::S4U => "S4U",
            LogonType::Interactive => "InteractiveToken",
        }
    }
}

/// Writes the XML and hands it to `schtasks`, returning its result rather than
/// interpreting it — the caller decides whether a failure is fatal or a reason
/// to try the other logon type.
fn register(
    executable: &Path,
    home: &Path,
    user: &str,
    logon: LogonType,
) -> Result<std::process::Output> {
    let xml = describe_task(executable, home, user, logon);

    // A file rather than a pipe: `schtasks /XML` takes a path, and it wants
    // UTF-16 — handed UTF-8 it reports a parse error that names a line number
    // and nothing useful about the encoding.
    let path = std::env::temp_dir().join("ralon-supervisor-task.xml");
    std::fs::write(&path, utf16(&xml))
        .with_context(|| format!("failed to write {}", path.display()))?;

    let created = schtasks(&["/Create", "/TN", TASK, "/XML"])
        .arg(&path)
        .arg("/F")
        .output()
        .context("failed to run schtasks — is it on PATH?")?;
    let _ = std::fs::remove_file(&path);
    Ok(created)
}

fn describe_task(executable: &Path, home: &Path, user: &str, logon: LogonType) -> String {
    let command = escape(&executable.display().to_string());
    let arguments = escape(&format!("daemon --home \"{}\"", home.display()));
    let user = escape(user);
    let logon = logon.xml();

    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Ralon enforces agent.lock in the workspaces registered with `ralon install`.</Description>
    <URI>\{TASK}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>{logon}</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// XML entity escaping. A path can hold `&`, and a user name on a domain can
/// hold most of the rest.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The inverse of [`escape`], for reading a path back out of the registration.
fn unescape(text: &str) -> String {
    // `&amp;` last: doing it first would turn `&amp;lt;` into `<`.
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Whatever `schtasks` decided to write this time.
///
/// It is not consistent, and the document is not a reliable witness about
/// itself. `schtasks /Query /XML` emits a declaration that says
/// `encoding="UTF-16"` and then writes single-byte characters to a redirected
/// pipe; `schtasks /Create /XML` refuses to read anything *but* UTF-16. So the
/// bytes are what decides here, and the declaration is ignored.
///
/// Found by reading a real registration rather than a fixture: decoding as
/// UTF-16 unconditionally turned every path into interleaved rubbish, `status`
/// found no `<Command>` element, and a registration pointing at a deleted binary
/// went on being reported as healthy — which is the one thing this parser
/// exists to catch.
fn decode(bytes: &[u8]) -> String {
    let utf16 = match bytes {
        [0xFF, 0xFE, ..] => true,
        // No mark, so look for the shape instead: UTF-16LE ASCII puts a zero
        // byte after every character, and UTF-8 XML never starts `<\0`.
        [_, 0, ..] => true,
        _ => false,
    };
    if !utf16 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let bytes = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
    let (pairs, _odd) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16_lossy(&units)
}

/// UTF-16LE with a byte order mark, which is what `schtasks /XML` reads.
fn utf16(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// `schtasks` writes its complaint to stdout about as often as to stderr.
fn message(output: &std::process::Output) -> String {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let trimmed = combined.trim();
    if trimmed.is_empty() {
        format!("exit code {}", output.status.code().unwrap_or(-1))
    } else {
        trimmed.replace('\r', "").replace('\n', " ")
    }
}

// ---------------------------------------------------------------------------
// The user's `PATH`, which is where the hook's command has to be findable.
// ---------------------------------------------------------------------------

/// Adds `directory` to the user's `PATH`. `Ok(false)` means it was already there.
///
/// Done through the registry rather than with `setx`, and that is not a
/// preference. `setx` truncates the value it writes at 1024 characters and says
/// nothing about it — on a developer's machine, where `PATH` is routinely longer
/// than that, running it is how you lose half of your `PATH` permanently.
///
/// The value's *type* is preserved, which matters as much as its content: a
/// `PATH` stored as `REG_EXPAND_SZ` usually contains `%USERPROFILE%\...`
/// entries, and rewriting it as `REG_SZ` leaves those literal — so every one of
/// them stops resolving, in a way that looks nothing like this command's fault.
pub fn add_to_path(directory: &Path) -> Result<bool> {
    edit_path(directory, pathvar::with)
}

/// Removes `directory` from the user's `PATH`. `Ok(false)` means it was not there.
pub fn remove_from_path(directory: &Path) -> Result<bool> {
    edit_path(directory, pathvar::without)
}

fn edit_path(directory: &Path, change: fn(&str, &str) -> Option<String>) -> Result<bool> {
    let directory = directory.display().to_string();
    let key = open_environment()?;

    let outcome = (|| {
        let (current, kind) = read_path(key)?;
        // No change means no write. The registry is not touched at all unless
        // there is something to do, which is what keeps a re-run of `install`
        // from being a risk taken for nothing.
        let Some(updated) = change(&current, &directory) else {
            return Ok(false);
        };
        write_path(key, &updated, kind)?;
        Ok(true)
    })();

    unsafe { RegCloseKey(key) };

    if matches!(outcome, Ok(true)) {
        // Without this, the new value reaches only processes started after the
        // next logon. Explorer rebroadcasts it to everything it launches, so a
        // terminal opened afterwards sees it — the one already open does not,
        // which is why the caller says so.
        announce_the_change();
    }
    outcome
}

fn open_environment() -> Result<isize> {
    let mut key = 0isize;
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide("Environment").as_ptr(),
            0,
            KEY_READ | KEY_WRITE,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("could not open HKCU\\Environment (error {status})");
    }
    Ok(key)
}

/// The current `Path` value and the type it is stored as.
///
/// A missing value is not an error — a profile that has never had anything
/// added to it has no `Path` at all — and it reads as empty, stored the way
/// Windows itself stores it.
fn read_path(key: isize) -> Result<(String, u32)> {
    let name = wide(PATH_VALUE);
    let mut kind = 0u32;
    let mut size = 0u32;

    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok((String::new(), REG_EXPAND_SZ));
    }
    if status != ERROR_SUCCESS {
        bail!("could not read the user PATH (error {status})");
    }
    // Anything else would be a value this code does not understand, and
    // overwriting it with a string is worse than refusing to.
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        bail!("the user PATH is stored as registry type {kind}, which Ralon will not rewrite");
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("could not read the user PATH (error {status})");
    }
    buffer.truncate(size as usize);

    let (units, _) = buffer.as_chunks::<2>();
    let wide: Vec<u16> = units
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .take_while(|unit| *unit != 0)
        .collect();
    Ok((String::from_utf16_lossy(&wide), kind))
}

fn write_path(key: isize, value: &str, kind: u32) -> Result<()> {
    let data = wide(value);
    let bytes: Vec<u8> = data.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let status = unsafe {
        RegSetValueExW(
            key,
            wide(PATH_VALUE).as_ptr(),
            0,
            kind,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("could not write the user PATH (error {status})");
    }
    Ok(())
}

fn announce_the_change() {
    let environment = wide("Environment");
    let mut ignored = 0usize;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            environment.as_ptr(),
            SMTO_ABORTIFHUNG,
            5_000,
            &mut ignored,
        )
    };
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

const PATH_VALUE: &str = "Path";
/// `(HKEY)(ULONG_PTR)((LONG)0x80000001)` — sign-extended, which is why it is
/// written as a cast through `i32` rather than as a `usize` literal.
const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WRITE: u32 = 0x0002_0006;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const HWND_BROADCAST: isize = 0xffff;
const WM_SETTINGCHANGE: u32 = 0x001A;
const SMTO_ABORTIFHUNG: u32 = 0x0002;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        key: isize,
        sub_key: *const u16,
        options: u32,
        desired: u32,
        result: *mut isize,
    ) -> i32;
    fn RegQueryValueExW(
        key: isize,
        value: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: isize,
        value: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        size: u32,
    ) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn SendMessageTimeoutW(
        window: isize,
        message: u32,
        wparam: usize,
        lparam: *const u16,
        flags: u32,
        timeout: u32,
        result: *mut usize,
    ) -> isize;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value as the *registry* has it.
    ///
    /// Deliberately not `std::env::var("PATH")`: this process's environment was
    /// fixed when it started and would not notice a write to the registry at
    /// all, so a test that checked it would pass against a function that did
    /// nothing.
    fn on_the_stored_path(directory: &Path) -> bool {
        let key = open_environment().expect("HKCU\\Environment is readable");
        let stored = read_path(key);
        unsafe { RegCloseKey(key) };
        let (value, _) = stored.expect("the user PATH is readable");
        pathvar::without(&value, &directory.display().to_string()).is_some()
    }

    /// Takes the marker back out however the test ends, so a panic between the
    /// two halves cannot leave an entry behind in a developer's real `PATH`.
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = remove_from_path(&self.0);
        }
    }

    #[test]
    fn a_directory_is_added_to_the_stored_path_and_taken_back_off() {
        // Read back rather than trusted. This family of call has form in this
        // repository: `SetEntriesInAcl` once returned `ERROR_SUCCESS` having
        // changed nothing, and the test that believed it passed for weeks.
        let marker = PathBuf::from(format!(r"C:\ralon-path-test-{}", std::process::id()));
        let _cleanup = Cleanup(marker.clone());

        assert!(
            !on_the_stored_path(&marker),
            "the marker was already on PATH, so this test proves nothing"
        );

        assert!(add_to_path(&marker).unwrap(), "reported nothing to add");
        assert!(
            on_the_stored_path(&marker),
            "add_to_path succeeded and the stored PATH did not change"
        );

        // Idempotent, because `ralon install` is documented as safe to re-run.
        assert!(
            !add_to_path(&marker).unwrap(),
            "a second install appended a duplicate"
        );

        assert!(
            remove_from_path(&marker).unwrap(),
            "reported nothing to remove"
        );
        assert!(
            !on_the_stored_path(&marker),
            "remove_from_path succeeded and the stored PATH did not change"
        );
        assert!(
            !remove_from_path(&marker).unwrap(),
            "uninstall would write the registry over an entry that is not there"
        );
    }

    fn task(logon: LogonType) -> String {
        describe_task(
            Path::new("C:\\ralon.exe"),
            Path::new("C:\\state"),
            "PC\\dev",
            logon,
        )
    }

    #[test]
    fn the_task_never_expires() {
        let xml = task(LogonType::S4U);
        // The whole reason this file exists rather than a `schtasks /Create`
        // one-liner: the default is PT72H, and a supervisor that stops after
        // three days unprotects every workspace without saying anything.
        assert!(
            xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"),
            "{xml}"
        );
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{xml}");
    }

    #[test]
    fn the_preferred_registration_runs_where_no_console_can_appear() {
        // The fix for a console window at every logon, and the reason it works:
        // S4U puts the process in session 0, which has no desktop. `Hidden` was
        // what this file used to rely on and it only affects the Task Scheduler
        // listing.
        assert!(task(LogonType::S4U).contains("<LogonType>S4U</LogonType>"));
    }

    #[test]
    fn the_fallback_is_the_one_that_always_registers() {
        let xml = task(LogonType::Interactive);
        assert!(
            xml.contains("<LogonType>InteractiveToken</LogonType>"),
            "{xml}"
        );
    }

    #[test]
    fn the_task_runs_on_battery() {
        // A laptop on battery queues a task whose settings are left at their
        // defaults — it never starts, `schtasks /Query` says `Queued`, and the
        // result code is 0, so nothing anywhere reports a problem. Found by
        // registering a probe task without these two lines and watching it sit
        // there.
        let xml = task(LogonType::S4U);
        assert!(
            xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"),
            "{xml}"
        );
        assert!(
            xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"),
            "{xml}"
        );
    }

    #[test]
    fn the_state_directory_is_passed_rather_than_inherited() {
        let xml = task(LogonType::S4U);
        assert!(xml.contains("daemon --home &quot;C:\\state&quot;"), "{xml}");
    }

    #[test]
    fn markup_in_a_path_cannot_break_out_of_the_element() {
        let xml = describe_task(
            Path::new("C:\\a&b\\ralon.exe"),
            Path::new("C:\\state"),
            "PC\\dev",
            LogonType::S4U,
        );
        assert!(xml.contains("C:\\a&amp;b\\ralon.exe"), "{xml}");
    }

    #[test]
    fn a_registered_path_survives_the_round_trip() {
        // `registered_path` reads back what `describe_task` wrote, so the
        // escaping has to be reversible — otherwise `status` reports a path
        // that does not exist and calls a working install broken.
        let original = "C:\\a&b\\o'brien\\ralon.exe";
        let xml = describe_task(
            Path::new(original),
            Path::new("C:\\state"),
            "PC\\dev",
            LogonType::S4U,
        );
        let start = xml.find("<Command>").unwrap() + "<Command>".len();
        let end = xml[start..].find("</Command>").unwrap() + start;
        assert_eq!(unescape(&xml[start..end]), original);
    }

    #[test]
    fn a_registration_is_read_back_whichever_encoding_it_arrives_in() {
        // Both are real. `/Create /XML` will read nothing but the first;
        // `/Query /XML` writes the second to a pipe while its own declaration
        // claims to be the first. Trusting the declaration meant `status` could
        // never see a dangling registration, on the machine where one existed.
        let element = "<Command>C:\\ralon.exe</Command>";
        assert!(decode(&utf16(element)).contains("C:\\ralon.exe"));
        assert!(decode(element.as_bytes()).contains("C:\\ralon.exe"));
    }

    #[test]
    fn utf16_without_a_byte_order_mark_is_still_utf16() {
        let mut encoded = utf16("<Command>C:\\ralon.exe</Command>");
        encoded.drain(..2);
        assert!(decode(&encoded).contains("C:\\ralon.exe"));
    }

    #[test]
    fn the_document_is_utf16_with_a_byte_order_mark() {
        let bytes = utf16("<a/>");
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(&bytes[2..4], &[b'<', 0]);
    }
}
