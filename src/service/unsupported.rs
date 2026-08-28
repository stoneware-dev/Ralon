//! Platforms with no supervisor, which in practice means Linux.
//!
//! Writing a systemd user unit here would take about twenty lines and would be
//! the single most dishonest thing in this codebase. The unit would install, the
//! service would start, `systemctl --user status ralon` would print `active
//! (running)` in green, and the daemon would sit there noticing `agent.lock`
//! files it can do absolutely nothing about — because every enforcement
//! mechanism Linux offers is *inherited* by a process before it runs, and none
//! can be *imposed* on one that is already running. A developer would read the
//! green text and stop wrapping their agent.
//!
//! So `install` fails instead, and says what does work. `ralon run` on Linux is
//! not the fallback: it is stronger than any supervisor on any platform here,
//! because the restriction becomes part of the process and there is no
//! supervisor left alive to kill.

use std::path::Path;

use anyhow::Result;

use super::Registration;

pub const SUPPORTED: bool = false;

/// See the note in `macos.rs`: a shell's `PATH` is in a file the developer owns.
pub const CAN_EDIT_PATH: bool = false;

pub fn add_to_path(_directory: &Path) -> Result<bool> {
    Ok(false)
}

pub fn remove_from_path(_directory: &Path) -> Result<bool> {
    Ok(false)
}

pub fn install(_executable: &Path, _home: &Path) -> Result<Registration> {
    anyhow::bail!("{}", unsupported_reason())
}

/// Nothing to stop or start where nothing can be registered.
pub fn stop() {}

pub fn start() -> Result<()> {
    Ok(())
}

pub fn uninstall() -> Result<bool> {
    Ok(false)
}

pub fn installed() -> bool {
    false
}

pub fn unsupported_reason() -> String {
    format!(
        "automatic background enforcement is not possible on {os}.\n\n\
         Every mechanism {os} has — a Landlock domain, a locked mount namespace — is\n\
         inherited by a process when it starts, and cannot be applied to a process that\n\
         is already running. A background service could notice agent.lock and would have\n\
         no way to act on it. The interfaces that could (`chattr +i`, fanotify permission\n\
         events) need root, and a root process that an agent can talk to is a worse\n\
         problem than the one being solved.\n\n\
         What works here, and is stronger than a supervisor:\n\
         \x20 ralon run -- <your agent>   the agent and every process it spawns, with the\n\
         \x20                             restriction inherited and nothing left to kill\n\
         \x20 ralon hook install          refuses the agents' own edit tools as well\n\n\
         Windows and macOS can impose a restriction from outside, so `ralon install`\n\
         works there. This is a difference in the kernels, not in Ralon.",
        os = std::env::consts::OS
    )
}
