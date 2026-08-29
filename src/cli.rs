use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::enforce::Backend;

/// Filesystem policy for AI coding agents.
///
/// `agent.lock` declares what AI-controlled processes may not modify, the same
/// way `.gitignore` declares what Git may not track.
#[derive(Debug, Parser)]
#[command(name = "ralon", version, about, long_about = None)]
pub struct Cli {
    /// Directory to look for agent.lock in (default: the current directory)
    #[arg(short = 'C', long = "dir", global = true, value_name = "DIR")]
    pub directory: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Set this machine up once. After that: declare a policy, and enforcement
    /// starts on its own
    ///
    /// Install once → declare policy → enforcement starts automatically. There
    /// is no third step and nothing to run inside a project: writing an
    /// `agent.lock` is what turns enforcement on, and deleting it is what turns
    /// enforcement off.
    ///
    /// Registers a background supervisor with the operating system — a logon
    /// task on Windows, a LaunchAgent on macOS — and records which directories
    /// your projects live in.
    ///
    /// Not available on Linux, where a restriction can only be inherited by a
    /// process at startup and never imposed on one already running. `ralon
    /// install` explains that rather than registering a service that could
    /// notice a policy and do nothing about it.
    Install {
        /// A directory your projects live in. Repeatable.
        /// Defaults to your home directory.
        #[arg(long = "scope", value_name = "DIR")]
        scope: Vec<PathBuf>,

        /// Cover only this project, not a directory of them
        ///
        /// For a single repository you want protected across reboots without
        /// declaring where all your code lives. The scope becomes this project
        /// and nothing else — no other directory on the machine is looked at.
        /// The supervisor it registers is the same one `--scope` registers;
        /// there is only ever one per user, and adding a scope later widens it
        /// rather than replacing it.
        #[arg(long, conflicts_with = "scope")]
        here: bool,

        /// How deep inside a scope a project may be
        #[arg(long, value_name = "N")]
        depth: Option<usize>,

        /// Do not configure the agents
        ///
        /// By default each enforced project gets the agent hook, so an agent is
        /// told "protected by Ralon" instead of being handed the raw OS error.
        /// Without it the policy is still enforced — the agent just reports
        /// `EBUSY: resource busy or locked` and has to work out why.
        #[arg(long)]
        no_hooks: bool,

        /// Print what would be registered and change nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// Manage the directories your projects live in
    ///
    /// A scope is where Ralon will honour an `agent.lock`. Repositories under one
    /// need no configuration of their own; repositories outside every scope are
    /// not enforced, and `ralon status` says so rather than looking protected.
    ///
    /// Where Ralon is installed has nothing to do with this. If your code is on
    /// another drive, say so:
    ///
    ///   ralon scope add D:\Projects
    Scope {
        #[command(subcommand)]
        action: ScopeAction,
    },

    /// Remove the background supervisor and release everything it holds
    Uninstall {
        /// Deregister the supervisor but leave the current enforcement in place
        #[arg(long)]
        keep_enforcement: bool,
    },

    /// Release one project so its policy can be edited, then take it back
    ///
    /// `agent.lock` protects itself, so a project the supervisor is enforcing
    /// cannot have its own policy rewritten — including by you. This is how you
    /// get it back for a while.
    Pause {
        /// Minutes before enforcement resumes on its own
        #[arg(long, value_name = "MINUTES", default_value_t = 15)]
        minutes: u64,

        /// Stay paused until `ralon resume`. You have to ask for this: a pause
        /// that is forgotten about is a project that stopped being protected
        /// without anyone deciding it should.
        #[arg(long, conflicts_with = "minutes")]
        indefinitely: bool,
    },

    /// Resume enforcement for a paused project
    Resume,

    /// The background supervisor itself. Started by the OS, not by people.
    Daemon {
        /// Stay in this process. What launchd and Task Scheduler want.
        #[arg(long)]
        foreground: bool,

        /// Do one pass and exit, printing what changed
        #[arg(long, conflicts_with = "foreground")]
        once: bool,

        /// Where to keep supervisor state, passed by the registered service
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
    },

    /// Write a starter agent.lock and wire up the agents
    Init {
        /// Overwrite an existing agent.lock
        #[arg(long)]
        force: bool,

        /// Write the policy only, and configure nothing
        #[arg(long)]
        no_hooks: bool,
    },

    /// Report what the policy protects, or whether given paths are protected
    ///
    /// Exits 1 if any given path is protected, which makes it usable as an
    /// agent pre-write hook.
    Check {
        /// Paths to test. With none, lists everything the policy protects.
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
    },

    /// Show the policy and which enforcement backends this kernel offers
    Status,

    /// Install or run the agent hook
    ///
    /// The hook refuses an agent's own edit tools before they touch a protected
    /// path. It is a courtesy layer, not enforcement — an agent that shells out
    /// bypasses it — but on platforms `run` cannot restrict, it is the only
    /// thing standing between an agent and your policy.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Protect the project against every process, with no command to wrap
    ///
    /// `run` protects the agent it starts. A guard protects the ones it does
    /// not: it holds the locks itself, and Windows refuses those to every
    /// process on the machine, so an agent started from anywhere — a terminal,
    /// an IDE, an extension, one installed next month — is refused without
    /// knowing Ralon exists. Start it once and stop it with `--stop`.
    Guard {
        /// Keep running after this terminal closes
        #[arg(long, conflicts_with = "stop")]
        detach: bool,

        /// Release a running guard and clear anything it left behind
        #[arg(long)]
        stop: bool,

        /// This *is* the background guard `--detach` started. Not for people:
        /// it means "you have no console, do not try to write to one".
        #[arg(long, hide = true, conflicts_with_all = ["detach", "stop"])]
        detached: bool,
    },

    /// Run a command that cannot modify the protected paths
    Run {
        /// Enforcement backend
        #[arg(long, value_enum, default_value_t = Backend::Auto)]
        backend: Backend,

        /// Print what would be enforced and exit
        #[arg(long)]
        dry_run: bool,

        /// Do not print the lock summary before running
        #[arg(short, long)]
        quiet: bool,

        /// Command to run, e.g. `ralon run -- claude`
        #[arg(
            value_name = "COMMAND",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<OsString>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScopeAction {
    /// Start honouring `agent.lock` under a directory
    ///
    /// Takes effect immediately: any project already there with a policy is
    /// enforced before this command returns.
    Add {
        /// Directories to cover. Repeatable.
        #[arg(value_name = "DIR", required = true)]
        directories: Vec<PathBuf>,
    },

    /// Show the scopes, and what is enforced in each
    List,

    /// Stop honouring `agent.lock` under a directory
    ///
    /// Releases every project it was enforcing there, before returning. Must
    /// name a scope exactly — a directory *inside* one cannot be carved out.
    Remove {
        /// Scopes to drop. Repeatable.
        #[arg(value_name = "DIR", required = true)]
        directories: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Wire the hook into an agent's configuration
    Install {
        /// Which agent to configure
        #[arg(long, value_enum, default_value_t = Agent::Auto)]
        agent: Agent,

        /// Print the configuration instead of writing it
        #[arg(long)]
        dry_run: bool,
    },

    /// Decide one edit, reading the agent's request on stdin
    ///
    /// This is what the installed hook calls. Parsing the request here rather
    /// than in a shell snippet keeps the configuration free of quoting, and
    /// means the hook behaves identically on every platform.
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    /// Only the agents this machine or project actually uses — those with a
    /// configuration directory here or in your home directory. Falls back to
    /// every agent when it can detect none, so a project is never left without
    /// the message. The default.
    Auto,
    /// Every agent below, whether or not it is used here. Use this to cover a
    /// tool you have not opened the project with yet.
    All,
    /// Claude Code — .claude/settings.json
    Claude,
    /// Cursor — .cursor/hooks.json
    Cursor,
    /// OpenCode — .opencode/plugins/ralon.js
    Opencode,
    /// GitHub Copilot in VS Code — .github/hooks/ralon.json
    Copilot,
    /// OpenAI Codex — .codex/hooks.json
    Codex,
    /// Gemini CLI — .gemini/settings.json
    Gemini,
    /// Google Antigravity — .agents/hooks.json
    Antigravity,
    /// Windsurf / Cascade — .windsurf/hooks.json
    Windsurf,
    /// Cline — .clinerules/hooks/PreToolUse
    Cline,
}
