//! Google Antigravity: `.agents/hooks.json`, `PreToolUse`.
//!
//! The odd one out in three ways, which is why it gets its own installer rather
//! than sharing Claude Code's:
//!
//! - The document is keyed by *hook name* first, with an `enabled` flag, and
//!   the events live inside that. So Ralon owns one named entry and leaves any
//!   others alone.
//! - The request arrives as `{"toolCall": {"name": ..., "args": {...}}}` with
//!   PascalCase argument names, which is why `hook::targets` compares keys
//!   after lowercasing and dropping underscores, and `hook::tool_name` knows to
//!   look inside `toolCall`.
//! - It refuses with `{"decision": "deny", "reason": ...}`, like Gemini CLI and
//!   unlike the `permissionDecision` agents.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use super::Installed;

pub const SETTINGS: &str = ".agents/hooks.json";

pub const EVENT: &str = "PreToolUse";

/// The name Ralon's entry lives under, so a second install replaces it and
/// hooks the project already had are untouched.
const NAME: &str = "ralon";

// Antigravity's heritage is Cascade, so its write tool is
// `replace_file_content`, alongside `write_to_file` and `create_file`. All three
// are covered by the shared verb matcher in `hook::write_matcher` — and unlike
// the list that used to live here, so is whatever the next build renames them
// to, as long as it still reads like a verb.

pub fn entry() -> Value {
    json!({
        "enabled": true,
        EVENT: [{
            "matcher": super::write_matcher(),
            "hooks": [{
                "type": "command",
                "command": super::COMMAND,
                "timeout": 15
            }]
        }]
    })
}

pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(SETTINGS);

    let mut document: Value = if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Same rule as everywhere else: a file that cannot be parsed is never
        // written over, because the alternative is destroying configuration the
        // user cannot get back.
        serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not valid JSON, so it will not be modified",
                path.display()
            )
        })?
    } else {
        Value::Object(Map::new())
    };

    let Some(fields) = document.as_object_mut() else {
        anyhow::bail!("{} does not contain a JSON object", path.display());
    };

    let replaced = fields.contains_key(NAME);
    fields.insert(NAME.to_string(), entry());

    let rendered = format!("{}\n", serde_json::to_string_pretty(&document)?);
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
