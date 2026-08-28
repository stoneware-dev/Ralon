//! A launchd LaunchAgent in `~/Library/LaunchAgents`.
//!
//! A user agent, not a daemon: it lives under the developer's home directory,
//! runs as the developer, and needs no `sudo` to install or remove. That is not
//! a convenience — a `LaunchDaemon` in `/Library` would run as root, and the
//! only thing Ralon does with the extra privilege is become a more interesting
//! target than the files it is protecting.
//!
//! `KeepAlive` does the supervising, so nothing here has to. launchd restarts
//! the process if it exits, starts it at login, and starts it again after a
//! reboot — the whole reason to register with the system rather than fork into
//! the background and hope.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use super::Registration;

pub const SUPPORTED: bool = true;

/// A shell's `PATH` here lives in whichever startup file that shell reads —
/// `.zshrc`, `.bash_profile`, `.config/fish/config.fish`, or a `paths.d` entry.
/// Picking one is a guess, and a wrong guess means Ralon has appended a line to
/// a file the developer maintains by hand and does not expect anyone else to
/// touch. So the line is printed and they run it.
pub const CAN_EDIT_PATH: bool = false;

pub fn add_to_path(_directory: &Path) -> Result<bool> {
    Ok(false)
}

pub fn remove_from_path(_directory: &Path) -> Result<bool> {
    Ok(false)
}

const LABEL: &str = "dev.stoneware.ralon.supervisor";

pub fn install(executable: &Path, home: &Path) -> Result<Registration> {
    let path = plist_path()?;
    let directory = path.parent().expect("a plist path always has a parent");
    std::fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;

    std::fs::write(&path, describe_agent(executable, home))
        .with_context(|| format!("failed to write {}", path.display()))?;

    // Replacing an existing registration: `bootstrap` fails if the label is
    // already loaded, and the failure looks the same as a broken plist.
    let _ = bootout();

    let mut warnings = Vec::new();
    if let Err(error) = bootstrap(&path) {
        warnings.push(format!(
            "{error:#} — the agent is written and will start at the next login; \
             `ralon daemon --foreground` shows what it would do now"
        ));
    }

    Ok(Registration {
        mechanism: "a launchd LaunchAgent",
        path: Some(path),
        warnings,
    })
}

/// Unloads the agent without removing the plist, so `install` can replace the
/// binary it is running from. `install` already calls `bootout` before
/// `bootstrap`; this is the same thing done earlier, before staging.
pub fn stop() {
    let _ = bootout();
}

/// Loads the agent again after [`stop`].
pub fn start() -> Result<()> {
    let path = plist_path()?;
    if !path.exists() {
        return Ok(());
    }
    bootstrap(&path)
}

pub fn uninstall() -> Result<bool> {
    let path = plist_path()?;
    if !path.exists() {
        return Ok(false);
    }
    // Unloaded before the file goes, or launchd keeps running a job whose
    // definition no longer exists and `installed()` reports nothing is there.
    let _ = bootout();
    std::fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

pub fn installed() -> bool {
    plist_path().map(|path| path.exists()).unwrap_or(false)
}

pub fn unsupported_reason() -> String {
    String::new()
}

/// `launchctl bootstrap`, with the pre-10.11 spelling behind it.
///
/// `bootstrap`/`bootout` are the supported verbs and `load`/`unload` are the
/// deprecated ones that still work everywhere. Trying the modern one first and
/// falling back means this keeps working on both without asking what version it
/// is running on.
fn bootstrap(path: &Path) -> Result<()> {
    let target = format!("gui/{}", uid());
    let modern = Command::new("launchctl")
        .arg("bootstrap")
        .arg(&target)
        .arg(path)
        .output()
        .context("failed to run launchctl")?;
    if modern.status.success() {
        return Ok(());
    }

    let legacy = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(path)
        .output()
        .context("failed to run launchctl")?;
    if legacy.status.success() {
        return Ok(());
    }

    anyhow::bail!(
        "launchctl would not start the supervisor: {}",
        message(&modern)
    )
}

fn bootout() -> Result<()> {
    let target = format!("gui/{}/{LABEL}", uid());
    let modern = Command::new("launchctl")
        .arg("bootout")
        .arg(&target)
        .output()
        .context("failed to run launchctl")?;
    if modern.status.success() {
        return Ok(());
    }

    let path = plist_path()?;
    let legacy = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&path)
        .output()
        .context("failed to run launchctl")?;
    if legacy.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "launchctl would not stop the supervisor: {}",
        message(&modern)
    )
}

fn uid() -> u32 {
    // Safety: `getuid` cannot fail and takes no arguments.
    unsafe { libc::getuid() }
}

fn plist_path() -> Result<PathBuf> {
    let home = crate::supervisor::registry::user_home()
        .context("could not find the home directory to install a LaunchAgent into")?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn describe_agent(executable: &Path, home: &Path) -> String {
    let logs = home.join("launchd.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{executable}</string>
		<string>daemon</string>
		<string>--foreground</string>
		<string>--home</string>
		<string>{home}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>{logs}</string>
	<key>StandardErrorPath</key>
	<string>{logs}</string>
</dict>
</plist>
"#,
        executable = escape(&executable.display().to_string()),
        home = escape(&home.display().to_string()),
        logs = escape(&logs.display().to_string()),
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

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
        trimmed.replace('\n', " ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_restarts_and_starts_at_login() {
        let plist = describe_agent(Path::new("/usr/local/bin/ralon"), Path::new("/state"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"), "{plist}");
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"), "{plist}");
    }

    #[test]
    fn the_agent_runs_in_the_foreground_because_launchd_supervises_it() {
        // A daemon that forked would exit immediately and `KeepAlive` would
        // restart it forever.
        let plist = describe_agent(Path::new("/usr/local/bin/ralon"), Path::new("/state"));
        assert!(plist.contains("<string>--foreground</string>"), "{plist}");
    }

    #[test]
    fn the_state_directory_is_passed_rather_than_inherited() {
        let plist = describe_agent(Path::new("/usr/local/bin/ralon"), Path::new("/state"));
        assert!(plist.contains("<string>--home</string>"), "{plist}");
        assert!(plist.contains("<string>/state</string>"), "{plist}");
    }
}
