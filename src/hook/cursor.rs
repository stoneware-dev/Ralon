//! Cursor: `.cursor/hooks.json`.
//!
//! Cursor's hooks take a command that reads the request on stdin and blocks by
//! exiting 2 — the same contract `ralon hook check` already implements, so the
//! configuration is all that differs.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use super::Installed;

pub const SETTINGS: &str = ".cursor/hooks.json";

/// Only the agent's own edits.
///
/// `beforeShellExecution` is deliberately absent, for the same reason `Bash` is
/// absent from the Claude matcher: the payload is a command string, and
/// deciding from it whether `sed -i .env` writes or `cat .env` reads is
/// guesswork. A hook registered on that event would have to allow everything it
/// could not judge — and a hook that always allows is worse than no hook,
/// because the configuration implies coverage that is not there.
const EVENTS: &[&str] = &["preToolUse"];

pub fn entry() -> Value {
    json!({
        "command": super::COMMAND,
        "type": "command",
        // Fail closed: if the check cannot run, refuse rather than allow. A
        // policy that evaporates when a binary is missing is not a policy.
        "failClosed": true,
        "timeout": 10
    })
}

fn is_ours(candidate: &Value) -> bool {
    candidate
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.contains(super::COMMAND))
}

pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(SETTINGS);

    let mut settings: Value = if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not valid JSON, so it will not be modified",
                path.display()
            )
        })?
    } else {
        json!({ "version": 1 })
    };

    let Some(root_object) = settings.as_object_mut() else {
        anyhow::bail!("{} does not contain a JSON object", path.display());
    };
    root_object.entry("version").or_insert_with(|| json!(1));

    let events = root_object
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(events) = events.as_object_mut() else {
        anyhow::bail!("{}: `hooks` is not an object", path.display());
    };

    let mut replaced = false;
    for event in EVENTS {
        let list = events
            .entry(*event)
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(list) = list.as_array_mut() else {
            anyhow::bail!("{}: `hooks.{event}` is not an array", path.display());
        };
        match list.iter().position(is_ours) {
            Some(index) => {
                list[index] = entry();
                replaced = true;
            }
            None => list.push(entry()),
        }
    }

    let rendered = format!("{}\n", serde_json::to_string_pretty(&settings)?);
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
