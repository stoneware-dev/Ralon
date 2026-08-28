//! GitHub Copilot in VS Code: `.github/hooks/ralon.json`, `PreToolUse`.
//!
//! Copilot reads every `*.json` under `.github/hooks/`, so unlike Claude Code
//! and Cursor there is nothing to merge into: Ralon owns one file and cannot
//! disturb a hook someone else wrote. Installing twice rewrites that file.
//!
//! Two differences from the others, both handled elsewhere rather than here:
//!
//! - The refusal is `hookSpecificOutput.permissionDecision = "deny"`, the same
//!   keys Claude Code reads, so `Decision::render` already satisfies it. Exit
//!   code 2 is a blocking error here too.
//! - The entry takes **no matcher**. The hook is called for every tool the
//!   agent uses, including reads, so `hook::decide` has to recognise a read and
//!   allow it — otherwise Copilot would be refused permission to *look at* a
//!   protected file, which is not what `agent.lock` says.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use super::Installed;

/// The file Ralon owns. The directory is a glob, so this sits beside anything
/// else the project has configured instead of replacing it.
pub const SETTINGS: &str = ".github/hooks/ralon.json";

/// The event whose entries this hook belongs to.
pub const EVENT: &str = "PreToolUse";

/// The entry to install.
pub fn entry() -> Value {
    json!({
        "type": "command",
        "command": super::COMMAND,
        // Long enough for a cold start on a large policy, short enough that a
        // wedged hook does not hang the agent. Copilot treats a timeout as a
        // non-blocking warning, so this failing open is the documented
        // behaviour rather than a surprise.
        "timeout": 15
    })
}

/// The whole file, since Ralon owns it.
pub fn document() -> Value {
    json!({ "hooks": { EVENT: [entry()] } })
}

// There is no `is_ours` here on purpose: Ralon owns `ralon.json` outright, so
// installing twice rewrites it and there is no list to search for our entry in.

pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(SETTINGS);
    let replaced = path.is_file();

    let rendered = format!("{}\n", serde_json::to_string_pretty(&document())?);
    if dry_run {
        print!("{rendered}");
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(&path, rendered)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(Installed { path, replaced })
}
