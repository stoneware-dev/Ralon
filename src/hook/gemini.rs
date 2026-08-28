//! Gemini CLI: `.gemini/settings.json`, `BeforeTool`.
//!
//! Two differences from the others, both real rather than cosmetic:
//!
//! - The event is `BeforeTool`, not `PreToolUse`.
//! - It refuses with `{"decision": "deny", "reason": ...}` on stdout and exit
//!   **0**, not with a non-zero exit. `hook check` prints that key alongside
//!   the others, so the one document works here too — but the exit code is not
//!   what makes it stick, which is worth knowing when reading the JSON.
//!
//! Its tools are snake_case (`write_file`, `replace`, `run_shell_command`) and
//! the matcher is a regex over that name.

use serde_json::{json, Value};

// Gemini CLI writes with `write_file` and edits in place with `replace`. Both
// are covered by the shared verb matcher in `hook::write_matcher`, rather than
// by a list kept in this file that only this file would remember to update.

pub const SETTINGS: &str = ".gemini/settings.json";

pub const EVENT: &str = "BeforeTool";

pub fn entry() -> Value {
    json!({
        "matcher": super::write_matcher(),
        "hooks": [{
            "type": "command",
            "command": super::COMMAND
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
