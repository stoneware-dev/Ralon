//! OpenCode: `.opencode/plugins/ralon.js`.
//!
//! OpenCode's hooks are JavaScript rather than configuration, and a
//! `tool.execute.before` hook blocks by throwing. The plugin is deliberately
//! tiny: it hands the request to `ralon hook check` and throws if that refuses,
//! so the decision still comes from one place and the plugin never needs to
//! learn what a policy is.

use std::path::Path;

use anyhow::{Context, Result};

use super::Installed;

pub const SETTINGS: &str = ".opencode/plugins/ralon.js";

pub const PLUGIN: &str = r#"// Written by `ralon hook install`. Safe to delete; safe to regenerate.
//
// Refuses any tool call that names a path agent.lock protects. The decision is
// made by `ralon hook check`, which reads the request on stdin and exits 2 to
// refuse — the same check every other agent's hook calls.
import { spawnSync } from "node:child_process";

export const RalonPlugin = async () => ({
  "tool.execute.before": async (input, output) => {
    const request = JSON.stringify({
      tool_name: input?.tool,
      tool_input: output?.args ?? {},
    });

    const result = spawnSync("ralon", ["hook", "check"], {
      input: request,
      encoding: "utf8",
    });

    // A missing binary means the policy cannot be checked. Say so rather than
    // waving the edit through: silence here looks exactly like protection.
    if (result.error) {
      throw new Error(
        "ralon is not on PATH, so agent.lock could not be checked: " +
          result.error.message,
      );
    }

    if (result.status === 2) {
      throw new Error(result.stderr.trim() || "blocked by agent.lock");
    }
  },
});
"#;

pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(SETTINGS);
    let replaced = path.is_file();

    if dry_run {
        print!("{PLUGIN}");
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(&path, PLUGIN)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(Installed { path, replaced })
}
