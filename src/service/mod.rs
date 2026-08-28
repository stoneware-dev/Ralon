//! Registering the supervisor with whatever starts things on this machine.
//!
//! One job: make `ralon daemon` come back after a reboot without anybody typing
//! it. Each platform has a per-user mechanism for exactly this and each is used
//! as intended — a Task Scheduler logon task on Windows, a launchd LaunchAgent
//! on macOS. Both are per-user by construction, which is why none of this asks
//! for administrator or root. A tool that protects you from an agent should not
//! be the reason there is a privileged process on the machine for an agent to
//! talk to.
//!
//! Linux has the mechanism (a systemd user unit) and nothing for it to run: see
//! `unsupported.rs`.

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[path = "unsupported.rs"]
mod platform;

pub mod pathvar;
pub mod stage;

use std::path::{Path, PathBuf};

use anyhow::Result;

/// Whether a supervisor can be registered here at all.
pub const SUPPORTED: bool = platform::SUPPORTED;

/// Whether `install` can put the staged binary on `PATH` itself, or has to say
/// how. See [`add_to_path`].
pub const CAN_EDIT_PATH: bool = platform::CAN_EDIT_PATH;

/// Makes the staged binary findable by name. `Ok(false)` means it already was.
///
/// This exists because of the one thing staging the binary took away. Every
/// agent hook Ralon writes invokes `ralon hook check` — a *name*, because those
/// files get committed and an absolute path would be one machine's home
/// directory in everybody's repository. The name resolving was, until this,
/// entirely the package manager's doing: `npm`, `bun`, `pip` and `cargo` each
/// put a copy on `PATH` and Ralon relied on it being there.
///
/// Then `install` started registering its own copy precisely so that the
/// package could be removed — and removing it takes `ralon` off `PATH` while
/// leaving the supervisor running and nine hooks installed that can no longer
/// run. Nothing reported it: the shell exits 1, no agent reads that as "deny",
/// so the edit goes ahead and is refused by the kernel with `EBUSY` instead.
/// Adding the staged directory here is what closes that, and it is appended
/// rather than prepended so a package manager's copy still wins when it exists.
pub fn add_to_path(directory: &Path) -> Result<bool> {
    platform::add_to_path(directory)
}

/// Takes it back off, for `uninstall`. `Ok(false)` means it was not there.
pub fn remove_from_path(directory: &Path) -> Result<bool> {
    platform::remove_from_path(directory)
}

/// What happened, in terms a person can check by hand afterwards.
pub struct Registration {
    /// The mechanism, named so it can be looked up: "a Task Scheduler logon
    /// task", "a launchd LaunchAgent".
    pub mechanism: &'static str,
    /// Where it was written, when it is a file.
    pub path: Option<PathBuf>,
    /// Anything that worked less well than it should have.
    pub warnings: Vec<String>,
}

/// Registers the supervisor to start at logon, and starts it now.
///
/// `home` is passed through to the daemon rather than left to the environment.
/// A service inherits the environment of whatever started it — the launchd
/// bootstrap context, the Task Scheduler — not the shell that ran `ralon
/// install`, so a `RALON_HOME` that was set here would silently not apply there,
/// and the daemon would look after a different set of workspaces than the one
/// the developer just configured.
pub fn install(executable: &std::path::Path, home: &std::path::Path) -> Result<Registration> {
    platform::install(executable, home)
}

/// Stops a running supervisor, leaving the registration in place.
///
/// `install` calls this before replacing the staged binary: a running supervisor
/// holds that file exclusively, so an upgrade has to ask it to let go rather
/// than discover it cannot write and fail.
pub fn stop() {
    platform::stop();
}

/// Starts the registered supervisor again. A no-op where none is registered.
pub fn start() -> Result<()> {
    platform::start()
}

/// Removes the registration. `false` means there was none.
pub fn uninstall() -> Result<bool> {
    platform::uninstall()
}

/// Whether the registration currently exists.
pub fn installed() -> bool {
    platform::installed()
}

/// The executable the registration points at, when that can be read back.
///
/// `None` means either that there is no registration or that this platform
/// cannot report one; [`installed`] is what distinguishes those.
pub fn registered_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        platform::registered_path()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// A registration left pointing at a binary that is no longer there.
///
/// The state a machine reaches by installing Ralon from a package manager,
/// running `ralon install`, and then removing the package — which is a
/// perfectly reasonable sequence and used to leave a logon task failing
/// silently forever. Staging the binary ([`stage`]) stops new installs getting
/// here; this reports the ones that already did.
pub fn dangling() -> Option<PathBuf> {
    let path = registered_path()?;
    (!path.exists()).then_some(path)
}

/// Whether a scope is somewhere a session-0 supervisor cannot reach.
///
/// Windows only, and specific to the S4U logon type that keeps the console
/// window from appearing: a process in session 0 runs without network
/// credentials, so a mapped drive or a UNC path resolves to nothing. Local
/// fixed drives — which is where source code almost always is — are unaffected.
///
/// Reported rather than refused. A scope on a network share is a legitimate
/// thing to want and the developer is the one who knows whether it matters.
pub fn network_scope_warning(root: &Path) -> Option<String> {
    if !cfg!(target_os = "windows") {
        return None;
    }
    let text = root.to_string_lossy();
    let unc = text.starts_with("\\\\") && !text.starts_with("\\\\?\\");
    if !unc {
        return None;
    }
    Some(format!(
        "{} is a network path. The supervisor runs in a session with no network \
         credentials — which is what keeps a console window from appearing at every \
         logon — so it will not see projects there. `ralon guard` and `ralon run` \
         still work in that directory.",
        root.display()
    ))
}

/// Why there is no supervisor here, for the platforms where there is not.
pub fn unsupported_reason() -> String {
    platform::unsupported_reason()
}
