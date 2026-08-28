//! Cline: `.clinerules/hooks/PreToolUse`.
//!
//! Not configuration — an executable named exactly after the event, which Cline
//! runs and reads JSON back from. So the hook is a two-line script that hands
//! the request to `ralon hook check` and lets its answer through unchanged;
//! the decision still comes from one place.
//!
//! Cline refuses on `{"cancel": true}` rather than on an exit code, which is
//! why `Decision::render` emits that key too. `exec` matters: it replaces the
//! shell with Ralon, so stdin, stdout and the exit code all pass through
//! untouched rather than being re-encoded by a wrapper.
//!
//! `PreToolUse` here fires for *every* tool, reads included, which is the other
//! reason `hook::decide` recognises a read and allows it.

use std::path::Path;

use anyhow::{Context, Result};

use super::Installed;

pub const SETTINGS: &str = ".clinerules/hooks/PreToolUse";

pub const SCRIPT: &str = r#"#!/bin/sh
# Written by `ralon hook install`. Safe to delete; safe to regenerate.
#
# Refuses any tool call that names a path agent.lock protects. `exec` hands the
# request straight to ralon, so its JSON and its exit code are Cline's answer.
exec ralon hook check
"#;

pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(SETTINGS);
    let replaced = path.is_file();

    if dry_run {
        print!("{SCRIPT}");
        return Ok(Installed { path, replaced });
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, SCRIPT).with_context(|| format!("failed to write {}", path.display()))?;

    // A hook that is not executable is a hook that does not run, and Cline has
    // no other way to be told about it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to make {} executable", path.display()))?;
    }

    Ok(Installed { path, replaced })
}
