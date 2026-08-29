//! The agent hook: refusing an edit before it happens.
//!
//! Enforcement lives in the kernel and covers processes. For the window before
//! `run` or `guard` is adopted, the hook is what an agent actually runs into.
//! It is deliberately modest: it refuses an agent's own edit tools, and nothing
//! else. An agent that shells out is not covered, and an agent that can edit
//! the project can delete the hook — which is why this is called a courtesy and
//! never a guarantee.
//!
//! Nine agents document a hook that can refuse an edit; one file each, and one
//! shared decision. They disagree about the settings file, the event name, the
//! request shape and the word for "no", so the differences live in those files
//! and everything below is common.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy};

pub mod antigravity;
pub mod claude;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod gemini;
pub mod opencode;
pub mod windsurf;

use crate::cli::Agent;

/// Paths an agent might name in a request, at any depth.
///
/// Agents disagree about the spelling and change it between versions, so the
/// check looks for all of them rather than one per agent — a key we fail to
/// recognise means an edit waved through, which is the failure that matters.
///
/// Compared after lowercasing and dropping underscores, so one entry covers
/// `file_path`, `filePath` and `FilePath` at once. They really do differ this
/// much: Claude Code sends `file_path`, Antigravity sends PascalCase arguments,
/// Gemini CLI sends snake_case ones.
const PATH_KEYS: &[&str] = &[
    "filepath",
    "path",
    "notebookpath",
    "targetfile",
    "abspath",
    "absolutepath",
    "oldpath",
    "newpath",
    "destination",
];

fn is_path_key(key: &str) -> bool {
    let normalised: String = key
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .flat_map(char::to_lowercase)
        .collect();
    PATH_KEYS.contains(&normalised.as_str())
}

/// Every path named anywhere in the request.
fn targets(request: &Value) -> Vec<String> {
    let mut found = Vec::new();
    collect(request, &mut found);
    found
}

/// Tools that only look at a file.
///
/// Some agents attach a matcher to the hook and only call it for edits; others
/// — GitHub Copilot among them — call it for *every* tool and expect the hook
/// to decide. Without this, a hook installed for one of those would refuse an
/// agent permission to **read** a protected file, which contradicts the whole
/// design: `agent.lock` says what must not change, and an agent is meant to be
/// able to read the policy that governs it.
///
/// Matched loosely and on the recognised side only. An unfamiliar tool name is
/// treated as a write, because the two mistakes are not equal: refusing a read
/// is an annoyance the user sees immediately, and allowing a write is the
/// failure this whole program exists to prevent.
const READ_ONLY_TOOLS: &[&str] = &[
    "read", "view", "open", "cat", "grep", "search", "glob", "list", "ls", "find", "fetch",
];

/// Every spelling of "this tool changes a file", as verbs.
///
/// Several agents scope their hook with a `matcher` — a regex over the tool
/// name — and each one used to carry its own hand-written list of the tool names
/// that agent was believed to have. That is a bug factory, and it produced a
/// real one: Claude Code's list said `Write|Edit|MultiEdit|NotebookEdit`, an
/// agent called a tool its own transcript displayed as `Update`, the hook never
/// ran, and the developer watched their agent be handed `EBUSY: resource busy or
/// locked` and conclude the repository was broken. Four files, four chances to
/// forget a spelling, and the failure is silent every time.
///
/// So the matcher is built from verbs rather than product names, and shared.
///
/// Every verb here is one some agent's real writing tool contains. That bar is
/// deliberate, because the matcher decides the *message* and not the
/// *protection*: a write the hook never sees is still refused by the kernel, and
/// all that is lost is Ralon getting to say why. Meanwhile every tool call the
/// matcher accepts costs a process — and on Windows, in some terminal hosts, a
/// console window that flashes and goes. An earlier version of this list also
/// carried `apply`, `save`, `modify`, `append`, `mkdir` and `touch`, which
/// matched no agent tool that `patch` and the rest did not already cover, and
/// did match a great many MCP tools (`save_memory`, `update_page`, `modify_*`)
/// that touch no file at all. Speculating cost something visible and bought
/// nothing.
///
/// `bash`, `shell`, `run` and `exec` are still absent, and still on purpose — a
/// hook cannot tell which paths an arbitrary command will touch, and a matcher
/// that pretended otherwise would give false confidence. That gap is closed by
/// enforcement, not by this.
const WRITE_VERBS: &[&str] = &[
    // Write, write_file, write_to_file · Edit, MultiEdit, NotebookEdit,
    // edit_file · create_file · replace, replace_file_content,
    // str_replace_editor · apply_patch · insert_edit_into_file · Update
    "write", "edit", "create", "replace", "patch", "insert", "update",
    // delete_file · remove_file · rename_file · move_file
    "delete", "remove", "rename", "move",
];

/// `WRITE_VERBS` as a regex alternation that matches either case.
///
/// Spelled `[Ww]rite` rather than with an inline `(?i)` flag: the matcher is
/// evaluated by each agent's own regex engine — JavaScript, Go, Rust, Python —
/// and a character class is the one thing all of them agree on. Substring
/// semantics, because every agent that has a matcher tests it that way, so
/// `[Ee]dit` covers `MultiEdit` and `NotebookEdit` without naming either.
pub fn write_matcher() -> String {
    WRITE_VERBS
        .iter()
        .map(|verb| {
            let mut characters = verb.chars();
            let first = characters.next().expect("no verb is empty");
            format!(
                "[{}{}]{}",
                first.to_ascii_uppercase(),
                first,
                characters.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// The program every agent's hook entry invokes, and the command it forms.
///
/// A *name*, not a path, and that is the load-bearing decision: these entries
/// are written into `.claude/settings.json` and eight siblings, all of which
/// people commit. An absolute path would be one developer's machine baked into
/// the repository — wrong for everybody else, and leaking a home directory into
/// git along the way.
///
/// The cost is that the name has to resolve, and [`resolves`] is what checks it.
pub const PROGRAM: &str = "ralon";
pub const COMMAND: &str = "ralon hook check";

/// Every settings file a hook can be installed into.
///
/// Listed once so "is a hook installed here" has one answer. A tenth agent is a
/// new module and an entry here.
pub const SETTINGS_FILES: &[&str] = &[
    claude::SETTINGS,
    cursor::SETTINGS,
    opencode::SETTINGS,
    copilot::SETTINGS,
    codex::SETTINGS,
    gemini::SETTINGS,
    antigravity::SETTINGS,
    windsurf::SETTINGS,
    cline::SETTINGS,
];

/// Whether this project has a hook to run at all.
pub fn installed_in(root: &Path) -> bool {
    SETTINGS_FILES
        .iter()
        .any(|relative| root.join(relative).is_file())
}

/// Where a shell would find [`PROGRAM`], or `None` if it would find nothing.
///
/// This is not a nicety. Every hook entry names the program rather than a path,
/// so a machine where the name does not resolve has nine installed hooks that
/// cannot run — and the failure is silent in the worst way: the shell exits 1,
/// which no agent reads as "deny", so the edit proceeds and is refused by the
/// kernel instead. The developer gets `EBUSY: resource busy or locked` and
/// concludes their repository is broken, which is the exact outcome the hook
/// exists to prevent.
///
/// That machine is not hypothetical. `ralon install` stages its own copy of the
/// binary precisely so the package manager's copy can be deleted — and once it
/// is, nothing is left on `PATH`.
pub fn resolves() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let pathext = std::env::var_os("PATHEXT");
    lookup(PROGRAM, &path, pathext.as_deref(), here(), &|candidate| {
        is_executable(candidate)
    })
}

/// How one platform spells a search path.
///
/// Passed in rather than read from `cfg!` inside the search, so the cases worth
/// testing — which are all about `PATHEXT` — can be checked from any host. It is
/// the rule the rest of this project follows: planning is platform-independent,
/// and only the syscalls are gated.
#[derive(Clone, Copy)]
struct Shell {
    separator: char,
    /// Whether a name needs an extension before anything will run it.
    extensions: bool,
}

const WINDOWS: Shell = Shell {
    separator: ';',
    extensions: true,
};

const POSIX: Shell = Shell {
    separator: ':',
    extensions: false,
};

fn here() -> Shell {
    if cfg!(windows) {
        WINDOWS
    } else {
        POSIX
    }
}

/// The search itself, with the environment and the filesystem passed in.
///
/// Separated so it can be tested against a Windows `PATH` from Linux and the
/// other way round — the interesting cases are all about `PATHEXT`, and none of
/// them need a real file.
fn lookup(
    program: &str,
    path: &std::ffi::OsStr,
    pathext: Option<&std::ffi::OsStr>,
    shell: Shell,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    for directory in path.to_string_lossy().split(shell.separator) {
        let directory = directory.trim_matches('"');
        if directory.is_empty() {
            continue;
        }
        for name in names(program, pathext, shell) {
            let candidate = Path::new(directory).join(&name);
            if exists(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// The filenames `program` could have on this platform.
///
/// `PATHEXT` is why this is not just `program.exe`. npm and bun put a `.cmd`
/// shim on `PATH`, never an `.exe` — so a check that looked only for `ralon.exe`
/// would report "not installed" on the most common way people install this, and
/// send them fixing something that was never broken.
fn names(program: &str, pathext: Option<&std::ffi::OsStr>, shell: Shell) -> Vec<String> {
    if !shell.extensions {
        return vec![program.to_string()];
    }
    let extensions = pathext
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut names = Vec::new();
    for extension in extensions.split(';') {
        let extension = extension.trim();
        if !extension.is_empty() {
            names.push(format!("{program}{}", extension.to_ascii_lowercase()));
        }
    }
    // Last, so an extension wins: a bare `ralon` on Windows is a file `cmd`
    // cannot run on its own, and finding it would be a false positive.
    names.push(program.to_string());
    names
}

/// A file something could actually execute.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    // Windows decides by extension, which `names` has already applied.
    #[cfg(not(unix))]
    {
        true
    }
}

/// What to tell someone whose hooks cannot run, or `None` when they can.
///
/// One sentence of diagnosis and one of remedy, because "not on PATH" on its own
/// invites the wrong conclusion — that Ralon is not installed, or that the
/// policy is not being enforced. Both are usually false: enforcement is in the
/// kernel and does not go through this at all.
pub fn unreachable_warning(home: &Path) -> Option<String> {
    if resolves().is_some() {
        return None;
    }
    Some(format!(
        "`{PROGRAM}` is not on PATH, so the agent hooks cannot run. Every policy is \
         still enforced; what is lost is that an agent gets the filesystem's error \
         rather than being told which file and which pattern. Add {} to PATH, or \
         reinstall the ralon package.",
        crate::service::stage::path(home)
            .parent()
            .map(|directory| directory.display().to_string())
            .unwrap_or_else(|| "Ralon's bin directory".to_string())
    ))
}

/// The tool being called, wherever this agent puts it.
fn tool_name(request: &Value) -> Option<&str> {
    request
        .get("tool_name")
        .or_else(|| request.get("toolName"))
        .or_else(|| request.get("tool"))
        // Antigravity nests it: `{"toolCall": {"name": ..., "args": {...}}}`.
        .or_else(|| request.get("toolCall").and_then(|call| call.get("name")))
        .and_then(Value::as_str)
}

fn only_reads(request: &Value) -> bool {
    let Some(tool) = tool_name(request) else {
        // No tool named: this is an agent whose hook is already scoped to edits
        // by a matcher, so there is nothing to narrow.
        return false;
    };
    let tool = tool.to_lowercase();

    // "read" matches `Read`, `read_file`, `ReadFile`; "edit" is never a read,
    // and neither is `NotebookEditRead`-style compounding, so a name that also
    // contains a writing verb loses.
    let writes = [
        "write", "edit", "create", "replace", "patch", "insert", "delete", "remove",
    ];
    READ_ONLY_TOOLS.iter().any(|name| tool.contains(name))
        && !writes.iter().any(|name| tool.contains(name))
}

fn collect(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                if is_path_key(key) {
                    if let Some(path) = child.as_str() {
                        found.push(path.to_string());
                    }
                }
                collect(child, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect(item, found)),
        _ => {}
    }
}

#[derive(Debug)]
pub struct Installed {
    pub path: PathBuf,
    /// True when an earlier Ralon hook was updated in place.
    pub replaced: bool,
}

/// Every concrete agent, in the order they are written and reported.
///
/// `Agent::All` and `Agent::Auto` are selectors over this list, not members of
/// it. A tenth agent is a new module, an entry here, and a row in [`MARKERS`].
const ALL_AGENTS: &[Agent] = &[
    Agent::Claude,
    Agent::Cursor,
    Agent::Opencode,
    Agent::Copilot,
    Agent::Codex,
    Agent::Gemini,
    Agent::Antigravity,
    Agent::Windsurf,
    Agent::Cline,
];

/// The directory whose presence means an agent is in use.
///
/// It is the agent's own configuration folder — the parent of the file the hook
/// goes in — found either in the project (this repository is opened with it) or
/// in the home directory (this developer uses it, even on a fresh clone the
/// agent has not written to yet). Both are the agent's choice of location, not
/// ours, which is what makes their presence evidence.
struct Marker {
    agent: Agent,
    dir: &'static str,
}

/// Copilot is deliberately absent. Its only footprint is `.github/`, which a
/// great many repositories have for reasons that have nothing to do with
/// Copilot, and it keeps no clean home-directory marker — so detecting it would
/// mean firing on `.github` constantly or missing it always. It is written under
/// `--agent all` or `--agent copilot`, never by detection.
const MARKERS: &[Marker] = &[
    Marker {
        agent: Agent::Claude,
        dir: ".claude",
    },
    Marker {
        agent: Agent::Cursor,
        dir: ".cursor",
    },
    Marker {
        agent: Agent::Opencode,
        dir: ".opencode",
    },
    Marker {
        agent: Agent::Codex,
        dir: ".codex",
    },
    Marker {
        agent: Agent::Gemini,
        dir: ".gemini",
    },
    Marker {
        agent: Agent::Antigravity,
        dir: ".agents",
    },
    Marker {
        agent: Agent::Windsurf,
        dir: ".windsurf",
    },
    Marker {
        agent: Agent::Cline,
        dir: ".clinerules",
    },
];

/// The agents this project or machine actually uses, with the home directory
/// passed in so the rules are a pure function of two paths — testable without an
/// ambient home.
///
/// A heuristic, and honest about being one: it reports an agent whose config
/// directory is present, which catches every agent that has run here and every
/// one the developer has set up, and misses one that leaves no such directory
/// (Copilot, or a tool used from another machine). Missing one costs the
/// *message*, never the protection — the kernel refuses the write regardless of
/// which hooks exist — so the failure is a raw OS error instead of a sentence,
/// which is the state `--agent all` exists to avoid.
fn detect_in(root: &Path, home: Option<&Path>) -> Vec<Agent> {
    MARKERS
        .iter()
        .filter(|marker| {
            root.join(marker.dir).is_dir()
                || home.is_some_and(|home| home.join(marker.dir).is_dir())
        })
        .map(|marker| marker.agent)
        .collect()
}

/// Turns a selector into the concrete agents to write.
///
/// `Auto` falls back to every agent when it detects none, so the choice is only
/// ever "trim to what is used" when something *is* used — a project is never
/// left with no hook because detection came up empty.
fn resolve_agents(root: &Path, agent: Agent, home: Option<&Path>) -> Vec<Agent> {
    match agent {
        Agent::All => ALL_AGENTS.to_vec(),
        Agent::Auto => {
            let detected = detect_in(root, home);
            if detected.is_empty() {
                ALL_AGENTS.to_vec()
            } else {
                detected
            }
        }
        one => vec![one],
    }
}

/// Installs the hook for the selected agents.
///
/// The default selector is `Auto`: only the agents in use here, because writing
/// nine configuration files into a project when eight of them are for tools it
/// has never seen is clutter the developer then has to explain in review. `All`
/// forces every one, for covering a tool not opened yet.
pub fn install_for(root: &Path, agent: Agent, dry_run: bool) -> Result<Vec<Installed>> {
    resolve_agents(
        root,
        agent,
        crate::supervisor::registry::user_home().as_deref(),
    )
    .into_iter()
    .map(|agent| install_one(root, agent, dry_run))
    .collect()
}

/// Writes one concrete agent's hook. The selectors are resolved away before
/// this is reached, so meeting one here is a bug rather than a case to handle.
fn install_one(root: &Path, agent: Agent, dry_run: bool) -> Result<Installed> {
    match agent {
        Agent::Claude => install(root, dry_run),
        Agent::Cursor => cursor::install(root, dry_run),
        Agent::Opencode => opencode::install(root, dry_run),
        Agent::Copilot => copilot::install(root, dry_run),
        Agent::Codex => install_codex(root, dry_run),
        Agent::Gemini => install_gemini(root, dry_run),
        Agent::Antigravity => antigravity::install(root, dry_run),
        Agent::Windsurf => install_windsurf(root, dry_run),
        Agent::Cline => cline::install(root, dry_run),
        Agent::All | Agent::Auto => {
            unreachable!("`{agent:?}` is a selector and is resolved before install_one")
        }
    }
}

fn install_windsurf(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        windsurf::SETTINGS,
        windsurf::EVENT,
        windsurf::entry(),
        windsurf::is_ours,
    )
}

fn install_codex(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        codex::SETTINGS,
        codex::EVENT,
        codex::entry(),
        codex::is_ours,
    )
}

fn install_gemini(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        gemini::SETTINGS,
        gemini::EVENT,
        gemini::entry(),
        gemini::is_ours,
    )
}

/// Adds the hook to Claude Code's settings, preserving everything already there.
pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        claude::SETTINGS,
        claude::EVENT,
        claude::entry(),
        claude::is_ours,
    )
}

/// The shape Claude Code, Codex and Gemini CLI all share: a settings file with
/// a `hooks` object, an array per event, and one entry of ours among whatever
/// else is already there.
///
/// Only the file, the event name, and the entry differ between them — which is
/// the argument for one function rather than three copies drifting apart.
fn install_settings(
    root: &Path,
    dry_run: bool,
    settings_file: &str,
    event: &str,
    entry: Value,
    is_ours: fn(&Value) -> bool,
) -> Result<Installed> {
    let path = root.join(settings_file);

    let mut settings: Value = if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Refusing to touch a file we cannot parse is the only safe move: the
        // alternative is overwriting settings the user cannot get back.
        serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not valid JSON, so it will not be modified",
                path.display()
            )
        })?
    } else {
        Value::Object(Map::new())
    };

    if !settings.is_object() {
        anyhow::bail!("{} does not contain a JSON object", path.display());
    }

    let events = settings
        .as_object_mut()
        .expect("checked above")
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if !events.is_object() {
        anyhow::bail!("{}: `hooks` is not an object", path.display());
    }

    let pre = events
        .as_object_mut()
        .expect("checked above")
        .entry(event.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(list) = pre.as_array_mut() else {
        anyhow::bail!("{}: `hooks.{}` is not an array", path.display(), event);
    };

    // Replace our own entry rather than stacking duplicates; leave every other
    // hook exactly where it was.
    let existing = list.iter().position(is_ours);
    let replaced = existing.is_some();
    match existing {
        Some(index) => list[index] = entry,
        None => list.push(entry),
    }

    let rendered = format!("{}\n", serde_json::to_string_pretty(&settings)?);
    if !dry_run {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(&path, rendered)
            .with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        print!("{rendered}");
    }

    Ok(Installed { path, replaced })
}

/// One protected path in a request, and the pattern that covers it.
pub struct Protected {
    /// Relative to the project root, which is how the policy names it.
    pub relative: String,
    pub pattern: String,
}

/// The decision the hook returns for one edit.
pub enum Decision {
    /// Nothing to say — the agent proceeds.
    Allow,
    /// Every protected path the request named, in the order it named them.
    ///
    /// All of them, not the first: a request touching two protected files used
    /// to be refused with only one named, so an agent correcting itself found
    /// the second one on the next attempt and the third on the one after — a
    /// round trip per protected path, each looking like a fresh failure. The
    /// refusal is for the whole tool call either way; what changes is that the
    /// agent learns everything it needs in one answer.
    Deny { protected: Vec<Protected> },
}

impl Decision {
    /// One refusal that every supported agent understands.
    ///
    /// Seven agents, four spellings of "no", one JSON document — they are
    /// different keys in the same object, so nothing has to choose between
    /// them:
    ///
    /// - `hookSpecificOutput.permissionDecision` — Claude Code, GitHub Copilot,
    ///   Codex.
    /// - `decision` + `reason` — Antigravity and Gemini CLI.
    /// - `permission` + `agent_message` — Cursor.
    /// - `cancel` + `errorMessage` — Cline.
    /// - exit code 2 — OpenCode's plugin, Windsurf, and Codex's fallback.
    ///
    /// Emitting a key an agent does not know costs nothing; failing to emit one
    /// it needs is an edit waved through. So this errs towards saying it in
    /// every dialect at once, which is also why there is one `hook check`
    /// rather than one per agent.
    pub fn render(&self) -> Option<String> {
        let Decision::Deny { protected } = self else {
            return None;
        };
        let reason = self.reason()?;
        // Additive, and deliberately so: an agent that does not know this key
        // ignores it and reads the prose, and one that does gets the same facts
        // without parsing a sentence. No agent's protocol is changed by a key it
        // has never heard of, which is the same bet the four spellings of "no"
        // above already make.
        let paths: Vec<Value> = protected
            .iter()
            .map(|entry| json!({ "path": entry.relative, "pattern": entry.pattern }))
            .collect();

        Some(
            json!({
                "decision": "deny",
                "reason": reason,
                "systemMessage": format!("ralon: {reason}"),
                "cancel": true,
                "errorMessage": reason,
                "permission": "deny",
                "agent_message": reason,
                "user_message": format!("ralon: {reason}"),
                "protectedPaths": paths,
                "hookSpecificOutput": {
                    "hookEventName": claude::EVENT,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
        )
    }

    /// What the agent is told, built from the paths rather than stored.
    ///
    /// The tail is the part that earns its length. An agent that is only told
    /// "denied" retries, renames around it, and shells out — all of which fail
    /// the same way — so it is told that too, and told what *will* work: the
    /// same call without the protected paths. Saying nothing was modified is
    /// not reassurance, it is the fact the agent needs to decide what to do
    /// next, because the whole tool call was refused before any of it ran.
    pub fn reason(&self) -> Option<String> {
        let Decision::Deny { protected } = self else {
            return None;
        };
        let listed = match protected.as_slice() {
            [] => return None,
            [one] => format!(
                "`{}` is protected by Ralon — it is listed in agent.lock (matches \
                 `{}`), so writes to it are refused.",
                one.relative, one.pattern
            ),
            many => format!(
                "{} paths in this request are protected by Ralon and writes to them \
                 are refused: {}.",
                many.len(),
                many.iter()
                    .map(|entry| format!("`{}` (matches `{}`)", entry.relative, entry.pattern))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };

        Some(format!(
            "{listed} This tool call was refused as a whole, so nothing in it was \
             modified — including any paths in it that are not protected. Re-issue it \
             without the protected path{}, and the rest of the work will go through. \
             This is not an error and nothing is broken; retrying, renaming around it, \
             or writing through a shell will fail the same way. You cannot change the \
             policy yourself — ask the developer. \
             Ralon: https://github.com/stoneware-dev/Ralon — a star helps other people \
             find it.",
            if protected.len() == 1 { "" } else { "s" }
        ))
    }
}

/// Decides one request. `start` is where to look for the policy when the
/// request names no path of its own.
pub fn decide(request: &str, start: &Path) -> Result<Decision> {
    let Ok(value) = serde_json::from_str::<Value>(request) else {
        // A request we cannot parse is not an edit we can judge. Blocking every
        // edit because a payload changed shape would make the agent unusable.
        return Ok(Decision::Allow);
    };

    // Reading a protected file is allowed, always and everywhere. Only agents
    // that call the hook for every tool ever reach this.
    if only_reads(&value) {
        return Ok(Decision::Allow);
    }

    // A request naming several paths — a multi-file edit — is refused if *any*
    // one of them is protected, and the whole call is refused rather than the
    // protected part of it. That is not a limitation being worked around: a tool
    // call is the agent's unit of work and Ralon cannot reach inside one to let
    // two of three edits land, so "allow the rest" would mean guessing that the
    // tool applies its edits independently. Guessing wrong writes a protected
    // file. Refusing the call writes nothing, and the reason below tells the
    // agent exactly how to get the allowed work done.
    //
    // Every protected path is collected, not just the first. The refusal is the
    // same either way; naming all of them is what lets an agent fix the request
    // in one attempt instead of one attempt per protected file.
    let mut protected: Vec<Protected> = Vec::new();
    for target in targets(&value) {
        let target = policy::absolute(Path::new(&target))?;
        let lookup = target.parent().unwrap_or(start);

        // No policy is not a violation: this project simply is not governed.
        let Ok(policy) = Policy::load(lookup).or_else(|_| Policy::load(start)) else {
            continue;
        };
        let matcher = Matcher::new(&policy.patterns)?;

        let Some(relative) = relative_path(&policy.root, &target) else {
            continue;
        };

        if let Some(pattern) = matcher.matched_pattern(&relative) {
            // Deduped: one request can name the same file under two keys — a
            // rename gives `oldPath` and `newPath`, and some agents repeat the
            // path in a nested argument — and listing it twice reads as two
            // separate problems.
            if !protected.iter().any(|seen| seen.relative == relative) {
                protected.push(Protected {
                    relative,
                    pattern: pattern.to_string(),
                });
            }
        }
    }

    if protected.is_empty() {
        return Ok(Decision::Allow);
    }
    // "Protected by Ralon" rather than the error the filesystem would have
    // produced. This is the one refusal whose wording is ours: without a hook
    // the agent reports whatever its runtime makes of the OS error — Node turns
    // a sharing violation into `EBUSY: resource busy or locked` — which reads as
    // a broken file rather than a policy, and sends the agent looking for a way
    // around it.
    Ok(Decision::Deny { protected })
}

/// Reads one request from stdin and decides it.
pub fn check(start: &Path) -> Result<Decision> {
    let mut request = String::new();
    std::io::stdin()
        .read_to_string(&mut request)
        .context("failed to read the hook request from stdin")?;
    decide(&request, start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude::SETTINGS;
    use serde_json::json;
    use std::ffi::OsStr;

    fn project(policy: &str) -> tempdir::TempDir {
        let dir = tempdir::TempDir::new();
        std::fs::write(dir.path().join("agent.lock"), policy).unwrap();
        dir
    }

    /// A minimal temp directory, so the tests need no dev-dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> TempDir {
                static COUNTER: AtomicU32 = AtomicU32::new(0);
                let path = std::env::temp_dir().join(format!(
                    "ralon-hook-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                TempDir(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn request(path: &Path) -> String {
        json!({
            "tool_name": "Write",
            "tool_input": { "file_path": path.to_string_lossy() }
        })
        .to_string()
    }

    #[test]
    fn denies_a_protected_path() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let decision = decide(&request(&dir.path().join(".env")), dir.path()).unwrap();
        let rendered = decision.render().expect("should deny");
        assert!(
            rendered.contains("\"permissionDecision\":\"deny\""),
            "{rendered}"
        );
        // The path and the claim, without depending on the punctuation between
        // them — the message quotes paths as `.env` so an exact-substring match
        // would break on formatting rather than on behaviour.
        assert!(rendered.contains(".env"), "{rendered}");
        assert!(rendered.contains("is protected by Ralon"), "{rendered}");
    }

    #[test]
    fn denies_the_policy_file_itself() {
        let dir = project("version: 1\nprotect: []\n");
        let decision = decide(&request(&dir.path().join("agent.lock")), dir.path()).unwrap();
        assert!(decision.render().is_some());
    }

    #[test]
    fn allows_an_unprotected_path() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let decision = decide(&request(&dir.path().join("src/App.tsx")), dir.path()).unwrap();
        assert!(decision.render().is_none());
    }

    #[test]
    fn allows_when_there_is_no_policy() {
        let dir = tempdir::TempDir::new();
        let decision = decide(&request(&dir.path().join("anything.txt")), dir.path()).unwrap();
        assert!(decision.render().is_none());
    }

    #[test]
    fn allows_a_request_it_cannot_parse() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        for request in ["", "not json", "{}", r#"{"tool_input":{}}"#] {
            let decision = decide(request, dir.path()).unwrap();
            assert!(decision.render().is_none(), "blocked on `{request}`");
        }
    }

    /// Agents that call the hook for *every* tool, not just edits, must still
    /// be allowed to read a protected file. `agent.lock` governs what may
    /// change; an agent that cannot read the policy cannot obey it.
    #[test]
    fn reading_a_protected_file_is_never_refused() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env");

        for tool in ["Read", "read_file", "view", "Glob", "grep_search"] {
            let request = json!({
                "tool_name": tool,
                "tool_input": { "file_path": target.to_string_lossy() }
            })
            .to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_none(), "{tool} was refused a read");
        }

        // And the writing tools still are refused, including ones whose names
        // merely contain a reading word.
        for tool in ["Write", "write_file", "apply_patch", "replace_file_content"] {
            let request = json!({
                "tool_name": tool,
                "tool_input": { "file_path": target.to_string_lossy() }
            })
            .to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_some(), "{tool} was allowed to write");
        }
    }

    /// Agents spell the same argument four different ways. A spelling we fail
    /// to recognise is an edit waved through.
    #[test]
    fn a_path_is_found_whatever_the_key_is_called() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env").to_string_lossy().into_owned();

        for key in [
            "file_path",
            "filePath",
            "FilePath",
            "TargetFile",
            "AbsolutePath",
            "abs_path",
        ] {
            let request =
                json!({ "tool_name": "Write", "tool_input": { key: target } }).to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_some(), "missed the path under `{key}`");
        }
    }

    /// Antigravity nests the whole call: `{"toolCall": {"name", "args"}}`.
    #[test]
    fn a_nested_tool_call_is_understood() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env").to_string_lossy().into_owned();

        let write = json!({
            "toolCall": { "name": "replace_file_content", "args": { "TargetFile": target } }
        })
        .to_string();
        assert!(decide(&write, dir.path()).unwrap().render().is_some());

        let read = json!({
            "toolCall": { "name": "view_file", "args": { "TargetFile": target } }
        })
        .to_string();
        assert!(decide(&read, dir.path()).unwrap().render().is_none());
    }

    /// A request naming several files, some protected and some not.
    fn multi(paths: &[&Path]) -> String {
        let edits: Vec<Value> = paths
            .iter()
            .map(|path| json!({ "file_path": path.to_string_lossy() }))
            .collect();
        json!({ "tool_name": "MultiEdit", "tool_input": { "edits": edits } }).to_string()
    }

    #[test]
    fn several_allowed_files_in_one_call_are_allowed() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let request = multi(&[&dir.path().join("a.txt"), &dir.path().join("b.txt")]);
        assert!(
            decide(&request, dir.path()).unwrap().render().is_none(),
            "a call touching only unprotected files was refused"
        );
    }

    #[test]
    fn one_protected_file_refuses_the_whole_call() {
        // The atomic case, and the decision this codifies: Ralon cannot reach
        // inside a tool call to apply two of three edits, so it refuses the call
        // rather than guess that the tool applies them independently. Guessing
        // wrong writes a protected file.
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let request = multi(&[
            &dir.path().join("a.txt"),
            &dir.path().join(".env"),
            &dir.path().join("b.txt"),
        ]);
        let decision = decide(&request, dir.path()).unwrap();
        let reason = decision.reason().expect("the mixed call was allowed");
        assert!(reason.contains(".env"), "{reason}");
        // And it says the allowed files were untouched, so the agent knows to
        // re-issue them rather than assuming they landed.
        assert!(reason.contains("nothing in it was modified"), "{reason}");
    }

    #[test]
    fn every_protected_path_is_named_not_just_the_first() {
        // The change this test exists for. Naming one at a time cost an agent a
        // round trip per protected file, each denial looking like a fresh
        // failure — so it would fix `.env`, retry, and be refused again for
        // `config/db.yaml` it was never told about.
        let dir = project("version: 1\nprotect:\n  - .env\n  - config/**\n");
        let request = multi(&[
            &dir.path().join(".env"),
            &dir.path().join("ok.txt"),
            &dir.path().join("config/db.yaml"),
        ]);
        let rendered = decide(&request, dir.path())
            .unwrap()
            .render()
            .expect("two protected paths were allowed");
        let value: Value = serde_json::from_str(&rendered).unwrap();

        let named: Vec<&str> = value["protectedPaths"]
            .as_array()
            .expect("protectedPaths is machine-readable")
            .iter()
            .map(|entry| entry["path"].as_str().unwrap())
            .collect();
        assert_eq!(named, vec![".env", "config/db.yaml"]);

        // The prose carries both too, with the pattern that caught each.
        let reason = value["reason"].as_str().unwrap();
        assert!(reason.contains(".env"), "{reason}");
        assert!(reason.contains("config/db.yaml"), "{reason}");
        assert!(reason.contains("config/**"), "{reason}");
        // The unprotected path in the same call is not listed as a problem.
        assert!(!reason.contains("ok.txt"), "{reason}");
    }

    #[test]
    fn one_file_named_twice_is_reported_once() {
        // A rename names the same path as `oldPath` and `newPath`. Listing it
        // twice reads as two separate problems.
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env").to_string_lossy().into_owned();
        let request = json!({
            "tool_name": "Rename",
            "tool_input": { "oldPath": target, "newPath": target }
        })
        .to_string();
        let rendered = decide(&request, dir.path()).unwrap().render().unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["protectedPaths"].as_array().unwrap().len(), 1);
    }

    /// One refusal, in every dialect at once.
    #[test]
    fn the_refusal_speaks_every_agents_language() {
        let rendered = Decision::Deny {
            protected: vec![Protected {
                relative: ".env".into(),
                pattern: ".env".into(),
            }],
        }
        .render()
        .unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();

        // Claude Code, Copilot, Codex.
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
        // Antigravity, Gemini CLI.
        assert_eq!(value["decision"], "deny");
        assert!(value["reason"].is_string());
        // Cursor.
        assert_eq!(value["permission"], "deny");
    }

    #[test]
    fn every_agent_gets_a_hook_and_installing_twice_replaces_it() {
        let dir = project("version: 1\nprotect:\n  - .env\n");

        let first = install_for(dir.path(), Agent::All, false).unwrap();
        assert_eq!(first.len(), 9, "an agent was dropped from `--agent all`");
        for installed in &first {
            assert!(
                installed.path.is_file(),
                "{:?} was not written",
                installed.path
            );
            assert!(!installed.replaced);
        }

        for installed in install_for(dir.path(), Agent::All, false).unwrap() {
            assert!(
                installed.replaced,
                "{:?} was written twice instead of replaced",
                installed.path
            );
        }
    }

    #[test]
    fn detection_reads_the_project_and_the_home() {
        let project = tempdir::TempDir::new();
        let home = tempdir::TempDir::new();

        // Nothing set up anywhere: nothing detected.
        assert!(detect_in(project.path(), Some(home.path())).is_empty());

        // A `.cursor` in the project means the project is opened with Cursor.
        std::fs::create_dir_all(project.path().join(".cursor")).unwrap();
        // A `.claude` in the home means the developer uses Claude, even here
        // where the repository has not been opened with it yet.
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();

        // Both, in MARKERS order — Claude before Cursor.
        assert_eq!(
            detect_in(project.path(), Some(home.path())),
            vec![Agent::Claude, Agent::Cursor]
        );
    }

    #[test]
    fn auto_writes_only_what_is_used_and_all_writes_everything() {
        let project = tempdir::TempDir::new();
        std::fs::create_dir_all(project.path().join(".cursor")).unwrap();

        // The whole point: a project that uses only Cursor is not given the other
        // eight files. Home passed as its own empty dir so the machine running
        // the test cannot add agents to the answer.
        let empty_home = tempdir::TempDir::new();
        let chosen = resolve_agents(project.path(), Agent::Auto, Some(empty_home.path()));
        assert_eq!(chosen, vec![Agent::Cursor]);
        assert!(
            !chosen.contains(&Agent::Claude),
            "auto wrote a hook for an agent the project does not use"
        );

        // `all` ignores detection entirely.
        assert_eq!(
            resolve_agents(project.path(), Agent::All, Some(empty_home.path())),
            ALL_AGENTS.to_vec()
        );
    }

    #[test]
    fn auto_falls_back_to_every_agent_when_it_detects_none() {
        // The safety valve. A project with nothing recognisable, on a machine
        // with nothing set up, is covered rather than left with no message — the
        // change only ever trims when it is sure, never leaves a project bare.
        let project = tempdir::TempDir::new();
        let empty_home = tempdir::TempDir::new();
        assert_eq!(
            resolve_agents(project.path(), Agent::Auto, Some(empty_home.path())),
            ALL_AGENTS.to_vec()
        );
    }

    #[test]
    fn copilot_is_never_detected_from_a_github_directory() {
        // `.github` is present in a great many repositories that have nothing to
        // do with Copilot, so its presence must not add Copilot to the detected
        // set. Paired with a real signal (`.cursor`) so the answer is genuine
        // detection and not the fall-back-to-all a `.github`-only project would
        // hit — a fall-back that includes Copilot by design, which is a different
        // question. Only `--agent all` or `--agent copilot` writes Copilot.
        let project = tempdir::TempDir::new();
        std::fs::create_dir_all(project.path().join(".github")).unwrap();
        std::fs::create_dir_all(project.path().join(".cursor")).unwrap();

        assert!(!detect_in(project.path(), None).contains(&Agent::Copilot));
        assert_eq!(
            resolve_agents(project.path(), Agent::Auto, None),
            vec![Agent::Cursor],
            "`.github` was treated as a Copilot marker"
        );
    }

    #[test]
    fn install_creates_settings_and_is_idempotent() {
        let dir = project("version: 1\nprotect:\n  - .env\n");

        let first = install(dir.path(), false).unwrap();
        assert!(!first.replaced);
        assert!(first.path.is_file());

        let second = install(dir.path(), false).unwrap();
        assert!(
            second.replaced,
            "a second install should replace, not stack"
        );

        let text = std::fs::read_to_string(&second.path).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let list = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(list.len(), 1, "duplicated the hook: {text}");
    }

    #[test]
    fn install_preserves_settings_it_did_not_write() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(SETTINGS),
            r#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .unwrap();

        install(dir.path(), false).unwrap();

        let text = std::fs::read_to_string(dir.path().join(SETTINGS)).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["model"], "opus", "dropped an unrelated setting");
        let list = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(list.len(), 2, "dropped an unrelated hook: {text}");
    }

    #[test]
    fn install_refuses_to_touch_unparseable_settings() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(SETTINGS), "{ not json").unwrap();

        let error = install(dir.path(), false).unwrap_err().to_string();
        assert!(error.contains("not valid JSON"), "{error}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(SETTINGS)).unwrap(),
            "{ not json",
            "modified a file it could not parse"
        );
    }

    /// A crude substring test for the alternation, standing in for the regex
    /// engine each agent actually uses. Every branch is a literal plus a
    /// two-character class, so this is exact for the pattern being generated.
    fn matcher_accepts(tool: &str) -> bool {
        write_matcher().split('|').any(|branch| {
            let Some((cases, rest)) = branch
                .strip_prefix('[')
                .and_then(|branch| branch.split_once(']'))
            else {
                return false;
            };
            cases
                .chars()
                .any(|first| tool.contains(&format!("{first}{rest}")))
        })
    }

    #[test]
    fn the_matcher_catches_every_writing_tool_these_agents_have() {
        // The list that a per-agent matcher was supposed to hold, asserted in
        // one place. `Update` is here because its absence from Claude Code's
        // hand-written list is what made this shared matcher necessary: the hook
        // never ran, and the agent was left to interpret `EBUSY` on its own.
        for tool in [
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
            "Update",
            "Create",
            "apply_patch",
            "write_file",
            "replace",
            "edit_file",
            "replace_file_content",
            "write_to_file",
            "create_file",
            "str_replace_editor",
            "insert_edit_into_file",
            "delete_file",
            "move_file",
            "rename_file",
        ] {
            assert!(
                matcher_accepts(tool),
                "the hook would never run for `{tool}`"
            );
        }
    }

    #[test]
    fn the_matcher_still_leaves_shell_tools_alone() {
        // Deliberate, and documented next to `WRITE_VERBS`: a hook cannot tell
        // which paths an arbitrary command will touch, so pretending to cover
        // them would be false confidence. Enforcement covers that gap instead.
        for tool in ["Bash", "shell", "run_command", "Read", "Grep", "Glob"] {
            assert!(
                !matcher_accepts(tool),
                "`{tool}` would fire the hook, which claims a guarantee it has not got"
            );
        }
    }

    #[test]
    fn the_matcher_does_not_fire_on_tools_that_touch_no_file() {
        // The other half of the trade-off. Each of these would cost a process —
        // and on Windows sometimes a console window that flashes — on every
        // call, to be told the tool touches nothing protected. They are the
        // reason the verb list is limited to spellings a real agent tool uses
        // rather than every word that sounds like writing.
        for tool in [
            "save_memory",
            "modify_settings",
            "append_to_log",
            "mkdir_remote",
            "touch_record",
        ] {
            assert!(
                !matcher_accepts(tool),
                "`{tool}` fires the hook for nothing"
            );
        }
    }

    /// One spelling for a path, so these tests mean the same thing on every
    /// host. `Path::join` uses the *running* platform's separator, so a Windows
    /// case checked from Linux produces `C:\dir/ralon.exe` — comparing that
    /// literally would make the test assert which machine it is running on.
    fn tidy(path: &str) -> String {
        path.to_lowercase().replace('\\', "/")
    }

    /// A stub filesystem: anything in the list is an executable file.
    fn present(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let owned: Vec<String> = paths.iter().map(|path| tidy(path)).collect();
        move |candidate: &Path| owned.contains(&tidy(&candidate.display().to_string()))
    }

    /// What the search found, spelled one way. Empty means it found nothing.
    fn resolved(path: &str, pathext: Option<&str>, shell: Shell, on_disk: &[&str]) -> String {
        lookup(
            "ralon",
            OsStr::new(path),
            pathext.map(OsStr::new),
            shell,
            &present(on_disk),
        )
        .map(|found| tidy(&found.display().to_string()))
        .unwrap_or_default()
    }

    #[test]
    fn a_cmd_shim_counts_as_finding_the_program() {
        // The case that made this necessary. npm and bun never put an `.exe` on
        // PATH — they put a `.cmd` shim — so a check that looked for `ralon.exe`
        // alone would report the most common installation as missing, and send
        // someone repairing a machine that was working.
        assert_eq!(
            resolved(
                r"C:\other;C:\Users\me\AppData\Roaming\npm",
                Some(".COM;.EXE;.BAT;.CMD"),
                WINDOWS,
                &[r"C:\Users\me\AppData\Roaming\npm\ralon.cmd"],
            ),
            "c:/users/me/appdata/roaming/npm/ralon.cmd"
        );
    }

    #[test]
    fn a_posix_path_is_searched_with_no_extension_at_all() {
        assert_eq!(
            resolved(
                "/usr/bin:/home/me/.cargo/bin",
                None,
                POSIX,
                &["/home/me/.cargo/bin/ralon"],
            ),
            "/home/me/.cargo/bin/ralon"
        );
    }

    #[test]
    fn nothing_on_path_is_reported_as_nothing() {
        // The state this whole check exists for: hooks installed, `ralon` gone.
        assert_eq!(
            resolved(
                r"C:\other;C:\also-not-here",
                Some(".EXE;.CMD"),
                WINDOWS,
                &[]
            ),
            ""
        );
    }

    #[test]
    fn the_first_directory_on_path_wins() {
        // Order is the whole reason `install` appends its own directory rather
        // than prepending it: a package manager's copy, which upgrades, must
        // beat the staged snapshot, which does not.
        assert_eq!(
            resolved(
                r"C:\first;C:\second",
                Some(".EXE"),
                WINDOWS,
                &[r"C:\first\ralon.exe", r"C:\second\ralon.exe"],
            ),
            "c:/first/ralon.exe"
        );
    }

    #[test]
    fn an_extension_beats_the_bare_name_on_windows() {
        // A bare `ralon` next to `ralon.exe` on Windows is not a program `cmd`
        // can run — matching it first would report a hook as runnable when it
        // is not.
        let names = names("ralon", Some(OsStr::new(".EXE;.CMD")), WINDOWS);
        assert_eq!(names, vec!["ralon.exe", "ralon.cmd", "ralon"]);
    }

    #[test]
    fn every_agent_invokes_the_command_the_check_looks_for() {
        // `resolves()` asks about one program name. If an agent's entry ever
        // named a different one, this check would be answering a question
        // nobody was asking — green while that agent's hook could not run.
        for (agent, entry) in [
            ("claude", claude::entry()),
            ("cursor", cursor::entry()),
            ("copilot", copilot::entry()),
            ("codex", codex::entry()),
            ("gemini", gemini::entry()),
            ("antigravity", antigravity::entry()),
            ("windsurf", windsurf::entry()),
        ] {
            let text = entry.to_string();
            assert!(
                text.contains(COMMAND),
                "{agent} does not invoke `{COMMAND}`: {text}"
            );
        }
        // The two that are scripts rather than JSON, checked as written.
        assert!(cline::SCRIPT.contains(COMMAND));
        assert!(opencode::PLUGIN.contains(COMMAND));
    }
}
