//! Holding a policy open with no command to supervise.
//!
//! `run` protects the agent it starts. A guard protects the agents it does
//! *not* start — every one of them, including the editor you already had open
//! and the tool you install next month, because a share-mode lock is refused to
//! every process on the machine and asks nothing of the process it refuses.
//! Start one and the project is protected until it is stopped, with no wrapper
//! command anywhere.
//!
//! What it gives up in exchange is inheritance. `run` on Linux *becomes* the
//! command, so there is nothing left to kill; a guard is a process, and killing
//! it releases the locks. It cannot use `run`'s job object either, since it has
//! no child to put in one. So this is the weaker of the two in exactly one way,
//! and the stronger in the way that matters most of the time.
//!
//! Two guards for the same project would each try to lock the same files and
//! the second would lose, so they rendezvous through a named pipe: creating it
//! is how a guard claims the project, waiting for a client is how it parks, and
//! connecting to it is how `--stop` asks for a clean release. It is an object in
//! the kernel rather than a pid file, so a guard that dies takes its claim with
//! it and leaves nothing to go stale.
//!
//! # Why a pipe and not an event
//!
//! It was a named event under `Local\`, with a comment saying that scoping the
//! claim to the logon session matched the boundary of the locks themselves.
//! That was wrong, and wrong in the direction that hurts: a share-mode lock is
//! a property of the file object and is refused to **every process on the
//! machine**, in any session. The claim was narrower than the thing it claimed.
//!
//! For a long time nothing noticed, because everything ran in one session. Then
//! the supervisor moved to session 0 — where Windows will not put a console
//! window, see `service/windows.rs` — and the mismatch became visible all at
//! once: a second guard started for a project that already had one, `status`
//! reported `guard not running` about a guard that was running, and `pause`
//! reported a project released while its files stayed locked. That last one is
//! the failure this whole tool exists to not have.
//!
//! A named pipe is the same kind of object with the right scope. `\\.\pipe\` is
//! one namespace for the whole machine, it needs no privilege to create in —
//! unlike `Global\`, which needs `SeCreateGlobalPrivilege` and would have meant
//! asking for administrator — and it carries both halves of the rendezvous:
//! `CreateNamedPipe` claims, `ConnectNamedPipe` parks, and a client connecting
//! releases. No polling, no pid, nothing to go stale.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{Context, Result};

use super::{acl, locks};
use crate::enforce::Plan;

/// Whether this platform can protect a process it did not start.
pub const AVAILABLE: bool = true;

/// What a guard here enforces with. The same backend `run` uses: on Windows the
/// mechanism was never inherited in the first place, so there is nothing weaker
/// about holding it from a background process instead of a wrapper.
pub const BACKEND: crate::enforce::Backend = crate::enforce::Backend::Locks;

const TRUE: i32 = 1;
const FALSE: i32 = 0;

/// A duplex pipe, and this must be the only instance of its name — which is
/// what turns "create the pipe" into "claim the project": the second guard's
/// `CreateNamedPipeW` is refused rather than given a second instance.
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
/// Byte stream, blocking. Nothing is ever sent through it — connecting *is* the
/// message — so the mode only has to be one both ends agree on.
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;

const INVALID_HANDLE: Handle = -1isize as Handle;
const ERROR_ACCESS_DENIED: u32 = 5;
/// What Windows returns when an open is refused because an existing handle's
/// share mode forbids it — i.e. the guard's own locks refusing a writer. It is
/// the whole of `running`, so it is the whole of "is this project protected".
const ERROR_SHARING_VIOLATION: i32 = 32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE_ACCESS: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;

/// Detach the guard from this console so it outlives the shell that started it.
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// Matches `job.rs`: one spelling of `HANDLE` for the whole backend.
type Handle = *mut c_void;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_length: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_time_out: u32,
        security_attributes: *mut c_void,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(pipe: Handle) -> i32;
    fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
    /// Only for [`stop_a_guard_from_before_the_pipe`]. Nothing current creates
    /// an event.
    fn OpenEventW(desired_access: u32, inherit_handle: i32, name: *const u16) -> Handle;
    fn SetEvent(event: Handle) -> i32;
    /// Wakes the parked `ConnectNamedPipe` from the console-signal handler,
    /// which runs on a different thread — which is exactly the case `CancelIo`
    /// cannot handle and this one can.
    fn CancelIoEx(handle: Handle, overlapped: *mut c_void) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *mut c_void,
        thread_attributes: *mut c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_information: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template: *mut c_void,
    ) -> Handle;
    fn SetStdHandle(std_handle: u32, handle: Handle) -> i32;
}

/// The pipe the parked guard is waiting on, so Ctrl-C can release it the same
/// way `--stop` does instead of killing the process and leaving the ACL behind.
static PARKED_ON: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn on_console_signal(_kind: u32) -> i32 {
    let pipe = PARKED_ON.load(Ordering::SeqCst);
    if pipe.is_null() {
        return FALSE;
    }
    unsafe { CancelIoEx(pipe, std::ptr::null_mut()) };
    // Handled: the wait returns, the locks are dropped in order, and the
    // process exits on its own terms rather than being torn down here.
    TRUE
}

/// A running guard: the locks, the ACL narrowing, and the claim on the project.
pub struct Session {
    claim: Handle,
    locks: locks::Locks,
    narrowing: acl::Narrowing,
    /// Anything the caller should say out loud before parking.
    pub warnings: Vec<String>,
}

impl Session {
    pub fn files(&self) -> usize {
        self.locks.files
    }

    pub fn directories(&self) -> usize {
        self.locks.directories
    }

    pub fn refused_directories(&self) -> usize {
        self.narrowing.directories()
    }

    /// Blocks until someone asks for the locks back.
    pub fn park(self) -> Result<()> {
        PARKED_ON.store(self.claim, Ordering::SeqCst);
        unsafe { SetConsoleCtrlHandler(Some(on_console_signal), TRUE) };

        // Returns when `stop` connects, when Ctrl-C cancels it, or immediately
        // with ERROR_PIPE_CONNECTED (535) if a client got in between the pipe
        // being created and this call. All three mean the same thing here —
        // stop holding the project — so the result is deliberately not
        // inspected. A guard that treated the race as an error would exit
        // without releasing anything.
        unsafe { ConnectNamedPipe(self.claim, std::ptr::null_mut()) };

        PARKED_ON.store(std::ptr::null_mut(), Ordering::SeqCst);
        // `self` is dropped here, in declaration order: the claim is released
        // last, so nothing can take the project over while the locks are still
        // coming off.
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            DisconnectNamedPipe(self.claim);
            CloseHandle(self.claim);
        }
    }
}

/// Takes the locks and claims the project.
pub fn start(root: &Path, plan: &Plan) -> Result<Session> {
    let claim = create_claim(root);
    if claim == INVALID_HANDLE {
        // Refused because one already exists is the ordinary case and deserves
        // the ordinary sentence; anything else is a real failure and says so.
        let error = unsafe { GetLastError() };
        if error == ERROR_ACCESS_DENIED {
            anyhow::bail!(
                "a guard is already protecting this project — `ralon guard --stop` first"
            );
        }
        anyhow::bail!("could not claim this project (Windows error {error})");
    }

    // Taken in the same order as `run`, and for the same reason: if a path
    // cannot be locked, nothing is claimed to be protected.
    let locks = match locks::acquire(&plan.pinned, &plan.protected) {
        Ok(locks) => locks,
        Err(error) => {
            unsafe { CloseHandle(claim) };
            return Err(error);
        }
    };
    let (narrowing, warnings) = acl::refuse_new_entries(&directories(&plan.protected));

    Ok(Session {
        claim,
        locks,
        narrowing,
        warnings,
    })
}

/// Asks a running guard to release. `false` means there was none.
pub fn stop(root: &Path) -> Result<bool> {
    if !running(root) {
        // Nothing holds the locks. A guard — current or legacy — always would,
        // so what is left is either a clean project or a process squatting the
        // claim pipe while protecting nothing, and a squatter needs no stopping.
        // The legacy path opens an *event*, which a squatter never created, so it
        // reports `false` here rather than being fooled the way the pipe was.
        return stop_a_guard_from_before_the_pipe(root);
    }

    // The locks are held. A current guard also holds a claim pipe and is woken by
    // connecting to it; a guard from before the pipe holds the same locks with
    // none, so reach it through its event instead.
    if !claim_pipe_present(root) {
        return stop_a_guard_from_before_the_pipe(root);
    }

    // Connecting is the whole message. Nothing is written and nothing is read:
    // the guard is blocked in `ConnectNamedPipe`, and a client arriving is what
    // it is waiting for.
    let client = unsafe {
        CreateFileW(
            claim_name(root).as_ptr(),
            GENERIC_READ | GENERIC_WRITE_ACCESS,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if client == INVALID_HANDLE {
        // It was there a moment ago, so either it has just exited on its own or
        // something is wrong. The loop below decides which, on the evidence.
        if !running(root) {
            return Ok(true);
        }
        anyhow::bail!(
            "found a guard but could not ask it to stop (Windows error {})",
            unsafe { GetLastError() }
        );
    }
    unsafe { CloseHandle(client) };

    // Asking is not the same as having been let go. Waiting for the claim to
    // disappear means that when this returns, the files really are writable —
    // otherwise the next command in a script races the guard's own cleanup.
    for _ in 0..100 {
        if !running(root) {
            return Ok(true);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::bail!("a guard was asked to stop and is still holding this project")
}

/// Whether a guard currently holds this project — the *property*, not a proxy.
///
/// A guard holds `agent.lock`, which every policy protects whether or not it
/// says so, with `FILE_SHARE_READ`: readers pass, and any attempt to open it
/// for writing is refused with a sharing violation, for every process on the
/// machine. So opening it for write and seeing that refusal *is* the question,
/// answered against the thing that actually protects the project.
///
/// This used to ask the claim pipe — `WaitNamedPipeW` on the name in
/// [`claim_name`] — whether an instance existed. That was spoofable, and by the
/// worst party: the name is a hash of the path, computable from this source, so
/// any same-user process could create a pipe of that name and hold nothing. It
/// showed `status` a running guard over a writable file and, worse, made the
/// supervisor record the project `enforced` and never start a real guard —
/// silent non-enforcement that no respawn recovered, because the check the
/// respawn depends on was the one being fooled. A share-mode lock cannot be
/// faked the same way: a process that makes this open fail is holding the file,
/// which is the protection, not a claim to it. This is the same move macOS
/// already makes — its `running` reads the immutable flag on `agent.lock`, the
/// property, not a note about it.
///
/// The pipe still exists, and is still how `stop` reaches a guard; it just no
/// longer stands in for enforcement. Probing the *file* holds no claim and
/// connects to nothing, so neither of the old objections — that testing by
/// creating the pipe made the poller race the guard for the claim, or that
/// connecting to it as a client would trip the stop rendezvous — applies here.
pub fn running(root: &Path) -> bool {
    let policy = root.join(crate::policy::POLICY_FILE);
    match std::fs::OpenOptions::new().write(true).open(&policy) {
        // Opened for write: nothing is holding it, so nothing is guarding this
        // project. The handle is dropped at the end of the match, unwritten.
        Ok(_probe) => false,
        // Refused by a share mode: a guard holds the file. Any other error — the
        // file is absent, or read-only — is not evidence of a lock and is not a
        // running guard.
        Err(error) => error.raw_os_error() == Some(ERROR_SHARING_VIOLATION),
    }
}

/// Whether this project's claim pipe currently exists.
///
/// Not "is a guard running" — that is [`running`], and the whole point of this
/// change is that the two are different questions. This one only decides *how*
/// to signal a guard that [`running`] has already confirmed is there: a current
/// guard carries a claim pipe and is woken by connecting to it, while one from
/// before the pipe existed holds the same locks with no pipe and is woken
/// through its legacy event instead.
fn claim_pipe_present(root: &Path) -> bool {
    /// Answer at once rather than waiting for the server's timeout — this asks
    /// whether the name exists, it is not an attempt to connect.
    const NMPWAIT_NOWAIT: u32 = 1;

    unsafe { WaitNamedPipeW(claim_name(root).as_ptr(), NMPWAIT_NOWAIT) != 0 }
}

/// Releases a guard left over from a version that rendezvoused on a named
/// event, so that upgrading does not strand one.
///
/// Without this, a guard started before the upgrade holds its files with a claim
/// the new binary cannot see: `--stop` reports there was no guard, `uninstall`
/// says it released everything, and the files stay locked until the machine is
/// rebooted or the process is found in Task Manager. That is the exact
/// experience this release is meant to stop happening, so it would be a poor
/// trade to fix it for package managers and cause it for upgrades.
///
/// Deletable in a later release, once no guard could plausibly predate the pipe.
/// The event is still `Local\`, so this can only reach a guard in this session —
/// which is the only place a pre-upgrade guard can be, since the supervisor that
/// runs in session 0 is itself newer than this code.
fn stop_a_guard_from_before_the_pipe(root: &Path) -> Result<bool> {
    const EVENT_MODIFY_STATE: u32 = 0x0002;

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in root.to_string_lossy().to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    let name = wide(format!("Local\\ralon-guard-{hash:016x}"));

    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, FALSE, name.as_ptr()) };
    if event.is_null() {
        return Ok(false);
    }
    unsafe {
        SetEvent(event);
        CloseHandle(event);
    }
    // Nothing to wait for: the old guard's claim is invisible to `running`, so
    // there is no property here that could be polled. It releases its locks on
    // the way out, in the same order it always did.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(true)
}

/// Creates the one and only instance of this project's claim pipe.
fn create_claim(root: &Path) -> Handle {
    unsafe {
        CreateNamedPipeW(
            claim_name(root).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1, // one instance, so the second guard is refused
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    }
}

/// Starts a guard that outlives this console, and waits to see it come up.
///
/// Reporting "started" for a process that died on its first syscall would be
/// the worst kind of lie this tool can tell, so the claim is what is waited
/// for, not the spawn.
///
/// `CreateProcess` rather than `std::process::Command`, for one reason:
/// inheritance is all or nothing. `Command` has to pass `bInheritHandles =
/// TRUE` to hand over stdio, and the child then inherits *every* inheritable
/// handle the shell gave this process — including the pipe a shell reads
/// output from. A guard holding that pipe open for the rest of the day means
/// `ralon guard --detach | anything` never finishes, long after every process
/// the shell is waiting on has exited. Observed, not theorised.
pub fn detach(root: &Path) -> Result<()> {
    let executable = std::env::current_exe().context("could not find the ralon executable")?;
    let mut command_line = wide(format!(
        "\"{}\" --dir \"{}\" guard --detached",
        executable.display(),
        root.display()
    ));

    let mut startup: StartupInfoW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut information: ProcessInformation = unsafe { std::mem::zeroed() };

    let started = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE, // inherit nothing at all
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null_mut(),
            std::ptr::null(),
            &startup,
            &mut information,
        )
    };
    if started == 0 {
        anyhow::bail!(
            "could not start a background guard (Windows error {})",
            unsafe { GetLastError() }
        );
    }
    unsafe {
        CloseHandle(information.thread);
        CloseHandle(information.process);
    }

    // Thirty seconds, which looks absurd for a process that claims the project
    // in about a hundred milliseconds — until the binary is one Windows has not
    // scanned before. Measured on a freshly built `ralon.exe`: 2.9 seconds to
    // first instruction, against a previous limit of three, because Defender
    // reads the whole image before letting it start. That is not an edge case,
    // it is the first run after every install and every upgrade — precisely when
    // `ralon install` calls this. Waiting longer costs nothing; giving up early
    // reports a failure for a guard that is about to work.
    for _ in 0..600 {
        if running(root) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    anyhow::bail!(
        "a background guard was started but never claimed the project — \
         run `ralon guard` in this terminal to see why"
    )
}

/// Points this process's standard handles at `NUL`.
///
/// A detached guard inherits no handles, so `GetStdHandle` gives it nothing to
/// write to — and Rust's `println!` *panics* when a write fails. A background
/// process that dies the first time it mentions a warning would be a guard
/// that stops guarding, so the handles are made real and pointed at nothing.
pub fn silence_standard_handles() {
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const STD_INPUT: u32 = -10i32 as u32;
    const STD_OUTPUT: u32 = -11i32 as u32;
    const STD_ERROR: u32 = -12i32 as u32;

    let null = unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if null.is_null() || null == (-1isize as Handle) {
        return;
    }
    for handle in [STD_INPUT, STD_OUTPUT, STD_ERROR] {
        unsafe { SetStdHandle(handle, null) };
    }
}

/// Protected paths that are directories, which are the ones with the gap a
/// handle cannot cover.
fn directories(protected: &[PathBuf]) -> Vec<PathBuf> {
    protected
        .iter()
        .filter(|path| path.is_dir())
        .cloned()
        .collect()
}

/// Leftover ACL narrowing from a guard that was killed before it could undo it.
pub fn leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    acl::leftovers(&directories(protected))
}

/// Clears that leftover state.
pub fn clear_leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    acl::clear(&directories(protected))
}

/// A name in the kernel's pipe namespace, one per project directory.
///
/// `\\.\pipe\` is machine-wide, which is the boundary the locks themselves
/// have: a share-mode lock is refused to every process in every session, so a
/// claim visible in only one session described something narrower than what it
/// was claiming. That is not a tidiness point — the supervisor runs in session
/// 0 and every `ralon` a person types runs in theirs, so a session-local claim
/// meant `status` and `pause` could not see or stop the guard doing the work.
///
/// Hashed rather than spelled out because a pipe name cannot contain `\` after
/// the prefix, and a project path is mostly `\`. Lower-cased first, so the two
/// spellings of one directory are one claim.
fn claim_name(root: &Path) -> Vec<u16> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in root.to_string_lossy().to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }

    wide(format!("\\\\.\\pipe\\ralon-guard-{hash:016x}"))
}

/// A NUL-terminated UTF-16 string, which is what every call here wants.
fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_of(root: &str) -> String {
        let wide = claim_name(Path::new(root));
        String::from_utf16_lossy(&wide[..wide.len() - 1])
    }

    #[test]
    fn the_claim_is_visible_from_every_session() {
        // The bug this replaced: the claim lived under `Local\`, which scopes an
        // object to one logon session, while the locks it stood for are refused
        // machine-wide. Once the supervisor moved to session 0 that gap meant
        // `status` could not see the guard doing the work and `pause` reported
        // projects released that were still locked.
        let name = name_of("D:\\projects\\app");
        assert!(name.starts_with("\\\\.\\pipe\\"), "{name}");
        assert!(!name.contains("Local\\"), "{name}");
        assert!(!name.contains("Global\\"), "{name}");
    }

    #[test]
    fn two_spellings_of_one_project_are_one_claim() {
        assert_eq!(name_of("D:\\Projects\\App"), name_of("d:\\projects\\app"));
    }

    #[test]
    fn different_projects_do_not_share_a_claim() {
        assert_ne!(name_of("D:\\projects\\app"), name_of("D:\\projects\\other"));
    }

    #[test]
    fn a_claim_pipe_without_the_locks_is_not_a_running_guard() {
        use std::os::windows::fs::OpenOptionsExt;

        // The share mode a guard holds its files with: readers pass, writers are
        // refused. Local to the test because that is the only place that plays a
        // guard; `running` needs the *result* of this mode, not the mode.
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        // The squat, in one function. The claim pipe's name is a hash of the
        // path, computed by `claim_name` right here — so any process can create
        // one and hold nothing. A `running` that trusted the pipe showed a guard
        // over a writable file and made the supervisor skip starting a real one.
        let dir = std::env::temp_dir().join(format!("ralon-squat-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join(crate::policy::POLICY_FILE);
        std::fs::write(&policy, "protect:\n  - .env\n").unwrap();

        // Control. Nothing holds the project: not running, and agent.lock is
        // writable — proved by writing it, not by an exit code.
        assert!(
            !running(&dir),
            "a guard was reported with nothing holding it"
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&policy)
                .is_ok(),
            "the control is wrong: agent.lock was not writable to begin with"
        );

        // The attack: hold the claim pipe and only the claim pipe.
        let squat = create_claim(&dir);
        assert_ne!(squat, INVALID_HANDLE, "could not create the claim to squat");
        assert!(
            claim_pipe_present(&dir),
            "the squat did not actually take the pipe, so the test proves nothing"
        );
        assert!(
            !running(&dir),
            "a claim pipe with no locks was mistaken for a running guard — the squat"
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&policy)
                .is_ok(),
            "agent.lock was not writable while only the pipe was held — \
             the pipe must protect nothing"
        );
        unsafe { CloseHandle(squat) };

        // Positive: a genuine guard holds agent.lock with FILE_SHARE_READ, and
        // that lock — the property — is exactly what `running` now reports.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&policy)
            .unwrap();
        assert!(
            running(&dir),
            "a genuinely locked agent.lock was not seen as a running guard"
        );
        drop(held);
        assert!(
            !running(&dir),
            "the lock was released and `running` still reported a guard"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_path_cannot_break_out_of_the_pipe_name() {
        // A pipe name takes no further `\` after the prefix, and a Windows path
        // is mostly `\`. Hashing is what makes the name legal; this is here so
        // that a future "readable names would be nicer" change has to notice.
        let name = name_of("D:\\projects\\app");
        assert_eq!(
            name.matches('\\').count(),
            "\\\\.\\pipe\\".matches('\\').count()
        );
    }
}
