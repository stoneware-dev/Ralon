//! Windsurf / Cascade: `.windsurf/hooks.json`, `pre_write_code`.
//!
//! The event *is* the matcher here — there is a separate hook for reading
//! (`pre_read_code`) and for writing (`pre_write_code`), so Ralon registers
//! only the second and reads are never in question.
//!
//! Blocking is by exit code 2 alone; no output shape is documented for it. The
//! entry carries both `command` and `powershell` because Cascade picks by
//! platform, and a hook that only works on macOS would be worse than none on a
//! Windows machine — which is where Ralon's own enforcement is strongest, but
//! the hook still has to be honest about covering the agent.

use serde_json::{json, Value};

pub const SETTINGS: &str = ".windsurf/hooks.json";

pub const EVENT: &str = "pre_write_code";

pub fn entry() -> Value {
    json!({
        "command": super::COMMAND,
        "powershell": super::COMMAND,
        "show_output": false
    })
}

pub fn is_ours(candidate: &Value) -> bool {
    ["command", "powershell"].iter().any(|key| {
        candidate
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains(super::COMMAND))
    })
}
