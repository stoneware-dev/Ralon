//! OpenAI Codex: `.codex/hooks.json`, `PreToolUse`.
//!
//! The same shape as Claude Code's, down to the field names — a `matcher`, a
//! nested `hooks` array, `type` and `command` — and the same two ways to
//! refuse: `permissionDecision: "deny"`, or exit code 2 with the reason on
//! stderr. `hook check` does both.
//!
//! The matcher is where Codex differs. Its edit tool is `apply_patch`, which
//! also matches `Edit` and `Write`, and the matcher is a regex over the tool
//! name — MCP tools included. `Bash` is left out for the reason it is left out
//! everywhere else: a hook cannot tell which paths a shell command will touch.

use serde_json::{json, Value};

// Codex's edit tool is `apply_patch`, alongside `Edit` and `Write`. All three
// are covered by the shared verb matcher in `hook::write_matcher`, which is
// built once rather than hand-listed per agent — the per-agent lists were how a
// tool spelling got missed and a hook silently stopped running.

/// Codex reads `hooks.json` beside the repo's config, or an inline `[hooks]`
/// table in `config.toml`. The JSON file is the one Ralon writes: it can be
/// created and replaced whole without touching settings someone else owns.
pub const SETTINGS: &str = ".codex/hooks.json";

pub const EVENT: &str = "PreToolUse";

pub fn entry() -> Value {
    json!({
        "matcher": super::write_matcher(),
        "hooks": [{
            "type": "command",
            "command": super::COMMAND,
            "statusMessage": "Checking agent.lock"
        }]
    })
}

pub fn is_ours(candidate: &Value) -> bool {
    candidate
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| command.contains(super::COMMAND))
            })
        })
}
