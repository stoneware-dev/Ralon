<p align="center">
  <img src="assets/ralon-mark.svg" width="88" height="88" alt="Ralon">
</p>

<h1 align="center">Ralon</h1>

<p align="center">
  <img src="assets/protected-by-ralon.svg" alt="protected by ralon">
</p>

A file in your project says what AI agents may not touch:

```yaml
# agent.lock
protect:
  - src/index.tsx
  - src/auth.ts
  - .env
  - config/**
  - .github/workflows/**
```

You set the machine up once:

```console
$ ralon install
registered a Task Scheduler logon task
scope      C:\Users\dev
```

**Install once → declare policy → enforcement starts automatically.**

There is no third step. A repository is protected *because it contains an
`agent.lock`*: write the file and the paths it names are refused to every process
on the machine; delete the file and enforcement stops. No command to run in the
project, no wrapper around the agent, nothing to remember after a reboot.

Those paths are read-only *to the kernel*. Not a linter, not a hook the agent can
talk its way past, not a prompt it can forget. `open()` fails, `rm` fails, and
the agent gets on with the work it is allowed to do.

On Linux there is no `ralon install`, and the reason is worth knowing rather than
working around — see [Two ways to enforce](#two-ways-to-enforce). There you start
the agent through Ralon instead, which is stronger:

```console
$ ralon run -- claude
ralon: 5 paths locked via the mount backend
```

```text
.gitignore  → what Git must not track
agent.lock  → what AI-controlled processes must not modify
```

Deliberately absent: no GUI, no account, no cloud service, no approval workflow,
no dependency on Claude, Cursor, Codex, Gemini or any other tool. It is a
binary, a config file, and two kernel features.

## Install

```console
$ cargo install ralon         # or from a checkout: cargo install --path .
$ npm install -g ralonlock    # prebuilt binary, wrapped
$ pip install ralonlock       # same binary
```

Or download a binary from the
[releases](https://github.com/stoneware-dev/Ralon/releases) — Linux builds are
static, so they run in any container.

The command is `ralon` however you install it. The policy file is called
`agent.lock`, not `ralon.lock`, on purpose: it is a format, not a product.
Anything could enforce it — this is one thing that does.

Ralon enforces on **Linux** (mount namespaces, Landlock), **macOS** (the Seatbelt
sandbox, or the immutable flag) and **Windows** (exclusive file handles). All of
them block *processes*, so they cover every agent — including ones that have
never heard of Ralon. `ralon status` says which one you are getting and why.

## Set the machine up once

**Windows and macOS.**

```console
$ ralon install                # register the supervisor
$ ralon scope add D:\Projects  # and say where your code actually is
$ ralon scope add E:\Work
```

For one repository and nothing else on the machine:

```console
$ cd my-project
$ ralon install --here         # this project is the whole scope
```

`install` registers a per-user background supervisor with the operating system —
a Task Scheduler logon task on Windows, a launchd LaunchAgent on macOS. No
administrator, no root, and it comes back after a reboot because the operating
system starts it. Re-running it is safe: scopes are additive and nothing is
duplicated.

It registers a *copy* of the binary in its own state directory, not wherever
`cargo`/`npm`/`pip` happened to put the one you ran — so a running supervisor
never makes its own package impossible to uninstall, and removing that package
never strands the registration. On Windows it also adds that directory to your
`PATH`, because the agent hooks it writes invoke `ralon` by name; those files get
committed, so they cannot hard-code one machine's path, which means the name has
to resolve. Open a fresh terminal after installing for the `PATH` change to take.

**Where Ralon is installed has nothing to do with what it protects.** On a first
run with no scope given it takes your home directory, because that is right often
enough to be a useful start — but plenty of Windows developers keep repositories
on `D:\` or `E:\`, and a home directory on `C:` says nothing about those.
`install` lists any fixed drive no scope reaches and prints the command:

```console
No scope covers D:\ — an agent.lock there is not enforced.
If that is where you keep code:
  ralon scope add D:\Projects
```

Managing scopes:

```console
$ ralon scope add D:\Projects     # takes effect before the command returns
$ ralon scope list                # every scope, and what is enforced in each
$ ralon scope remove D:\Projects  # releases its repositories on the way out
```

Scopes are whole trees and are kept disjoint. Adding one inside an existing scope
tells you it is already covered; adding one that contains existing scopes absorbs
them. Equivalent spellings — `d:\projects`, `D:\Projects\.`, a path through a
junction — resolve to a single scope, so they cannot end up as two that do not
recognise each other's repositories.

A scope is a boundary, not a surveillance area: it is the answer to "why doesn't
an `agent.lock` inside a downloaded archive lock files on my machine". Ralon
honours a policy only inside a directory you named.

After that, the whole workflow is:

```console
$ git clone git@github.com:you/app.git
$ cd app && $EDITOR agent.lock     # say what must not change
                                   # …that is the entire remaining step
```

Declaring the policy is what starts enforcement, and it takes under a second —
the operating system reports the new file (`ReadDirectoryChangesW` on Windows,
FSEvents on macOS; kernel notifications, not polling). A repository cloned next
month is covered by the same one-time setup.

Your agents are configured at the same moment, so an agent that reaches a
protected path is told **"protected by Ralon"**, which file, and which pattern
matched — instead of being handed `EBUSY: resource busy or locked` and left to
conclude the repository is broken. `--no-hooks` turns that off; enforcement does
not depend on it either way.

Day to day:

```console
$ ralon status                 # is this project protected, and by what
$ ralon pause                  # release this project for 15 minutes to edit its policy
$ ralon pause --indefinitely   # until you say otherwise
$ ralon resume                 # take it back now
$ ralon uninstall              # deregister, and hand every project back
```

`ralon pause` exists because `agent.lock` protects itself — which is the point of
it, and does mean you cannot edit your own policy while it is enforced. A pause
expires on its own by default: a pause that is forgotten about is a project that
stopped being protected without anyone deciding it should.

**Run `ralon uninstall` before removing the package.** It stops the supervisor,
hands every project back, and removes the staged binary and the `PATH` entry. The
supervisor is a background process the operating system starts, and no package
manager knows it exists — `npm` stopped running `preuninstall` scripts, and `pip`
and `cargo` never had the hook — so removing the `ralon`/`ralonlock` package first
leaves it running with nothing left to stop it, and on Windows leaves a file the
package manager cannot delete because a live process is mapped from it. That is
the "I had to kill it in Task Manager and delete the folder by hand" failure, and
`ralon uninstall` is how you avoid it.

### Why `agent.lock` is what activates it

The policy file is the declaration, and deliberately nothing more. It holds
patterns relative to itself — no PIDs, no sockets, no absolute paths, no daemon
state — so it is safe to commit and identical on every machine that checks the
repository out. The supervisor never writes to it.

It also grants nothing by existing. A policy is honoured only inside a scope you
named, so an `agent.lock` inside a downloaded archive or a dependency's source
tree protects nothing and locks nothing: being *honoured* is a permission the
developer gives once, to a directory, by name.

Even inside a scope the blast radius is small. Patterns are relative to the
policy file and `..`, absolute paths and `~` are rejected, so the worst a hostile
`agent.lock` can do is make its own directory read-only — which is why a broad
scope is a convenience question rather than a security one.

### Where the logs are

| | |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Ralon\supervisor.log` |
| macOS | `~/Library/Application Support/Ralon/supervisor.log` (plus `launchd.log` for anything launchd itself says) |
| Linux | `$XDG_STATE_HOME/ralon/supervisor.log`, or `~/.local/state/ralon/` |

`ralon status` and `ralon install` both print the exact path, so you never have
to guess. `RALON_HOME` relocates the whole directory — the config, the recorded
workspaces and the log. One line per event, timestamped; it starts over once it
passes a megabyte.

## Two ways to enforce

| | `ralon install` (a supervisor) | `ralon run -- <agent>` |
| --- | --- | --- |
| Covers | every process on the machine | the command, and everything it spawns |
| Applies to agents you did not start | yes | no |
| Survives a reboot | yes | n/a |
| Can be killed | yes — it is a process (Windows) | no — it *becomes* the command |
| Linux | not available | ✅ |
| macOS | ✅ weaker; see below | ✅ strongest here |
| Windows | ✅ | ✅ |

The split is a difference in kernels, not a gap in Ralon. Windows enforcement is
**held** by a process and refused to everyone else; Linux and macOS sandboxes are
**inherited** by a process before it runs. Inherited is the stronger of the two —
there is no supervisor to kill — but it cannot be imposed on a process you did
not start, which is exactly what a supervisor has to do.

So on **Linux there is no supervisor**, and `ralon install` fails and says why
rather than registering a systemd unit that would come up green and enforce
nothing:

```console
$ ralon install
ralon: automatic background enforcement is not possible on linux.
       …
       ralon run -- <your agent>   the agent and every process it spawns
```

On **macOS the supervisor is real but weaker than `ralon run`**, and this matters
enough to repeat: it enforces with `chflags uchg`, the user immutable flag. That
refuses every ordinary write from every process — editors, redirects, `rm`, `mv`,
`sed -i`, every agent's edit tool — and an agent that goes looking can undo it
with `chflags nouchg`. It is a narrowing, not a sandbox, and it is not equivalent
to process-level sandboxing. `ralon run` applies a Seatbelt profile the agent
cannot drop, see, or ask the kernel to lift. Use `run` for an agent you launch;
the supervisor is for the ones you do not.

On **Windows the two are the same mechanism** — share-mode handles either way —
so the supervisor gives up nothing except that it is a process and can be killed.

### Per-command enforcement

```console
$ ralon init                   # write a starter agent.lock, and wire up the agents
$ ralon status                 # what is protected, and what this machine can enforce
$ ralon check src/auth.ts      # is this path protected? exits 1 if it is
$ ralon check                  # list everything the policy protects right now
$ ralon run --dry-run -- npm test    # what would be locked, without locking it
$ ralon run -- claude          # the real thing
```

`ralon run` replaces itself with your command, so the agent keeps its terminal,
its exit code, and its signals. There is no supervisor process to kill and
nothing to keep running in the background.

`ralon guard --detach` is the same thing a supervisor does, for one project, by
hand — useful before `ralon install`, or on a machine where you would rather
nothing ran in the background. `ralon guard --stop` releases it.

Ralon refuses **writes to the paths you declared**, and nothing else. Reading is
untouched, so your build, tests, dev server, editor and `git` carry on normally;
everything outside the policy is untouched too. The only person it gets in the way
of is you, when you want to edit a protected file — which is what `pause` is for.

There is no way to refuse *only* an LLM agent and no one else. A process carries
no mark saying what it is, and agents write through `cmd`, `python`, `node` and
`git` — the same binaries you use. The hook below is the closest thing, and it is
defeatable for exactly that reason.

### When it is not working

| Situation | What happens |
| --- | --- |
| Ralon is not installed | Nothing is enforced. `agent.lock` is an ordinary file. |
| The supervisor is stopped or was never started | Projects it had already enforced **stay** enforced on macOS (the flag is on disk) and are **released** on Windows (the locks die with the process). `ralon status` reports both cases separately. |
| `agent.lock` is malformed | That project is not enforced, and says so: `ralon status` exits 2 and names the line. Nothing is half-applied, and a policy that cannot be read locks nothing rather than locking everything. |
| The project is outside every scope | Not enforced, and `ralon status` says exactly that — `policy found, but this project is outside every scope … it is NOT protected` — followed by the `ralon scope add` that covers it. |
| A scope's directory is gone (drive unplugged, share unmounted) | Everything else carries on. `ralon scope list` marks it `(unreachable)`. |
| The agent hook is missing | Still enforced — the agent just sees the filesystem's own error (`EBUSY`, `Access is denied`, `EPERM`) rather than being told why. `ralon hook install` fixes it. |
| The hook is installed but `ralon` is not on PATH | The same outcome, reached a nastier way: every hook entry invokes `ralon hook check` by name, a shell that cannot find it exits 1, and no agent reads 1 as a refusal — so the edit goes ahead and the kernel refuses it instead. Still enforced. `ralon status` now says so and how to fix it; `ralon install` appends its own directory to PATH on Windows. |
| A console window appears on Windows at logon, or at `ralon install` | Fixed. The logon task ran with an interactive token, and a console program started by something with no console of its own gets a fresh, visible one; the task's `Hidden` setting does not affect that, and this project claimed it did. The task now runs in session 0, where there is no desktop for a window to appear on. A machine whose policy withholds the batch logon right falls back to the old behaviour and says so. |
| A console window flashes when the agent edits a file | Your agent is spawning `ralon hook check` without hiding the window — a spawn flag Ralon does not control. Nothing Ralon starts in the background has one: the supervisor runs in session 0 and guards are created detached. `ralon install --no-hooks`, or `ralon hook install --agent <one>`, reduces how often it is spawned; enforcement is unaffected either way. |
| `agent.lock` is deleted | Enforcement is released and the record dropped — including when it was deleted while the supervisor was down. |

`ralon status` answers "is the supervisor registered", "is it running" and "is
*this project* protected" as three separate lines, because the first two have a
comfortable answer that means nothing about the third.

### The hook

`ralon init` installs this; `ralon hook install` does it on its own, and
`--no-hooks` skips it.

It writes a refusal into the configuration of every agent that documents a hook
capable of blocking an edit before it happens — nine of them:

| Agent | File | How it refuses |
| --- | --- | --- |
| Claude Code | `.claude/settings.json` | `permissionDecision: deny` |
| GitHub Copilot (VS Code) | `.github/hooks/ralon.json` | `permissionDecision: deny` |
| OpenAI Codex | `.codex/hooks.json` | `permissionDecision: deny`, or exit 2 |
| Cursor | `.cursor/hooks.json` | `permission: deny` |
| Gemini CLI | `.gemini/settings.json` | `decision: deny` |
| Google Antigravity | `.agents/hooks.json` | `decision: deny` |
| Cline | `.clinerules/hooks/PreToolUse` | `cancel: true` |
| Windsurf / Cascade | `.windsurf/hooks.json` | exit 2 |
| OpenCode | `.opencode/plugins/ralon.js` | throws |

`--agent` picks one. One `ralon hook check` serves all nine: the refusal is a
single JSON document carrying every one of those keys, plus exit code 2, since
emitting a key an agent ignores costs nothing and omitting one it needs is an
edit waved through.

Every entry names the **program**, not a path — these files get committed, and an
absolute path would be one developer's machine in everybody's repository. So the
name has to resolve: `ralon install` appends its own directory to your `PATH` on
Windows, and prints the line to add elsewhere. `ralon status` says so when a
project has hooks it cannot run, because that state looks exactly like Ralon not
being involved at all.

Two are deliberately **not** installed, for the same reason:

- **JetBrains Junie** ignores project-local `.junie/config.json` hooks by
  default, so an installed hook would silently do nothing. Add it to
  `~/.junie/config.json` yourself if you want it — the format is Claude Code's.
- **Roo Code** has no hook API yet (it is an open feature request). Its
  `.rooignore` would block edits, but it blocks *reads* too, and protected
  files are meant to stay readable.

For those two — and for Aider, Amazon Q, and whatever ships next month — use
`ralon run` or `ralon guard`. They restrict the *process*, so they never needed
to know which agent was running in the first place. That is the point of the
whole design: agents are listed here only because a hook has to speak each
one's configuration format.

Be clear about what it is worth. It covers the agent's **edit tools**; it does
not cover a shell command the agent runs, because a hook cannot tell which
paths `sed -i` will touch. On Linux the kernel catches those anyway. Elsewhere
they get through, which is why the hook is a courtesy and `run` is the
guarantee.

`ralon check` exits 1 for a protected path if you would rather wire it up
yourself, or gate a CI job on it.

## Protected by Ralon — the badge

If your project ships an `agent.lock`, say so. Drop one of these into your
README so anyone reading it — and any tool scanning it — knows agents are held
to a policy here.

<p align="center">
  <img src="assets/protected-by-ralon.svg" alt="protected by ralon">
</p>

**Markdown** (self-hosted SVG, no third-party service):

```markdown
[![protected by ralon](https://raw.githubusercontent.com/stoneware-dev/Ralon/master/assets/protected-by-ralon.svg)](https://github.com/stoneware-dev/Ralon)
```

**Markdown** (Shields.io, if you already use it elsewhere):

```markdown
[![protected by ralon](https://img.shields.io/badge/protected%20by-ralon-ffb454)](https://github.com/stoneware-dev/Ralon)
```

**HTML:**

```html
<a href="https://github.com/stoneware-dev/Ralon"><img src="https://raw.githubusercontent.com/stoneware-dev/Ralon/master/assets/protected-by-ralon.svg" alt="protected by ralon"></a>
```

The badge is a claim about your repository, not a check on it — it says an
`agent.lock` is present and meant to be enforced. What actually enforces it is
`ralon install` or `ralon guard` on the machine the agent runs on; the badge is
the sign on the door, not the lock.

## The policy file

```yaml
protect:            # paths relative to agent.lock
  - .env            # a file
  - config          # a directory, and everything under it
  - config/**       # the same thing, spelled out
  - src/*.ts        # * stops at /
  - "**/secrets.json"   # ** does not
```

- `agent.lock` protects itself. An agent that can rewrite the policy has no
  policy.
- Patterns are relative to the policy file. `..`, absolute paths, `~` and `!`
  are rejected rather than quietly reinterpreted.
- Any command finds the policy by walking up from the working directory, the
  same way `git` finds `.git`.
- `version:` is optional and means `1`. Files that state it still work;
  `version: 2` is refused. Unknown keys are refused too, so `protects:` is an
  error rather than a policy that protects nothing — and an **empty**
  `agent.lock` is refused for the same reason, because "enforced, protecting
  nothing" is the one status that must never be reassuring.

## What the guarantee actually is

Under `ralon run`, for every protected path, in the sandboxed process and
all of its descendants:

| Attempt | Result |
| --- | --- |
| write, append, truncate, `cp` over it | denied |
| delete it, rename it away | denied |
| replace it by renaming another file over it | denied |
| create files inside a protected directory | denied |
| rename or remove a directory on the way to it | denied |
| read it | allowed |
| everything else in the project | untouched |

These are the cases in `tests/enforcement.rs`, which runs the attacks for real
against a real sandbox and then checks the file from outside it.

The restriction is inherited across `fork` and `exec` and cannot be dropped: a
Landlock domain is one-way, and the mount namespace is locked before your
command starts, so `umount` and bind-mount tricks fail from inside.

### Where it stops

- **Only what you launch** — unless a supervisor or a guard is running. Under
  `ralon run` the policy protects the processes it starts; `ralon install` covers
  the rest of the machine on Windows and macOS; on Linux an agent started some
  other way is not restricted.
- **A supervisor is a process, on Windows.** Killing it releases the locks. `run`
  has nothing to kill, which is why it is the stronger of the two where both
  exist. On macOS the opposite: the flag survives everything, including Ralon
  being killed, which is why a killed supervisor leaves state behind rather than
  losing protection.
- **The macOS supervisor does not pin unprotected ancestors.** With
  `src/deep/secret.txt` protected but `src/` and `src/deep/` not, an agent can
  `mv src/deep src/moved`, recreate `src/deep`, and put a different file at the
  declared path — the original bytes stay immutable under their new name and are
  no longer the ones anything reads. macOS conflates "may not be renamed" with
  "may not accept new entries" in one flag, so pinning ancestors would freeze the
  project root. **Protect the directory rather than the file inside it** and the
  gap closes; Ralon warns when a policy has this shape. Every other backend pins
  ancestors and `ralon run` on macOS does not have the gap at all.
- **Only what exists.** A protected path that is not on disk yet cannot be
  bind-mounted. `status` and `run` warn about patterns matching nothing. (Under
  the landlock backend such paths cannot be created at all, which is stricter.)
- **Not against root.** A process that can become root outside the namespace can
  undo anything. This defends against an agent doing something stupid or
  overreaching, not against an attacker with your password.
- **Not a secret store.** Protected files stay readable. `agent.lock` says what
  must not *change*; if a file must not be *read*, do not put it in the project.

## Backends

`run` picks the strongest backend the platform offers. `ralon status` shows
what is available, and `--backend mount|landlock|locks` pins the choice.

**locks** (Windows) — Ralon holds every protected file open allowing readers
and refusing writers, so writing, deleting, renaming or replacing one fails
with a sharing violation, for every process on the machine. ACLs would not do:
an agent runs as the same user, so any permission Ralon can set it can unset. A
handle is not a permission.

The one thing a handle cannot express is "and nothing may be added here", since
creating a file opens no existing object. That gap is covered by a deny ACE on
protected directories while Ralon runs — a narrowing rather than a guarantee,
because the agent owns the directory and an owner's `WRITE_DAC` cannot be
denied. It refuses every ordinary create; `security.md` is explicit about what
it does not refuse.

The protection lasts as long as Ralon does. A command started by `run` is tied
to a job object that dies with Ralon, so it cannot outlive the locks; a guard
has no child to tie, so killing one releases them.

**seatbelt** (macOS) — the policy compiled to a Seatbelt profile and applied
with `sandbox_init`, inherited across `exec` and by every descendant. The only
backend that can state a denial directly, so it is precise like `mount`,
inherited like `landlock`, and the only one whose rules cover files that do not
exist yet — a protected directory refuses new entries without any special
handling. `run --dry-run --backend seatbelt` prints the profile. `sandbox_init`
is deprecated and used anyway, for the reason given in `security.md`: it is what
every sandbox on macOS uses, and the supported alternative needs a signed
`.app`.

**immutable** (macOS) — `chflags uchg` on each protected path. The only mechanism
on macOS that can be *imposed* on a process nobody started, which is what makes
`ralon install` and `ralon guard` possible there; `run` never selects it and
`--backend auto` never returns it. A directory's flag refuses new entries, and
each file inside a protected directory is flagged in its own right. It is a
narrowing an agent can undo with one unprivileged command, it does not pin
ancestors, and `security.md` states both. Implementing it reversed an earlier
decision in this project not to — the reasoning, and why it changed, is in
`enforce/macos/immutable.rs`.

**mount** (default) — read-only bind mounts inside a user + mount namespace,
locked by entering a second namespace so they cannot be undone. Every parent
directory of a protected path is turned into a mount point too, so no directory
on the way to it can be renamed or removed. Precise: nothing outside the
protected paths behaves differently. Needs unprivileged user namespaces, which
some hardened distros and container runtimes disable.

**landlock** — the kernel LSM, Linux 5.13+. Needs no namespaces, so it works
where user namespaces are blocked. Landlock rules are additive — a rule can only
grant *more* access than its parents, never less — so "everything except this
file" has to be expressed by granting every sibling along the way instead. The
consequence is visible and worth knowing: **directories leading to a protected
path become create-restricted**. With `src/index.tsx` protected, everything in
`src/` and in the project root stays writable, but new files cannot be created
directly in either; new files inside `tests/`, `docs/` or any other subtree are
fine. `run --dry-run --backend landlock` lists exactly which directories are
affected.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | fine |
| 1 | a path is protected (`check`), or the plan cannot be enforced (`--dry-run`) |
| 2 | error: no policy, bad policy, no usable backend, command failed to start |

Otherwise `run` exits with your command's own status.

## EXAMPLE

![A Claude Code session refusing to modify a protected file](image.png)

## Documentation

- [`DESIGN.md`](DESIGN.md) — **start here.** The pipeline, the three process
  models, the capability matrix for all five backends, why one of them cannot
  pin ancestors, and the designs that were rejected
- [`architecture.md`](architecture.md) — deeper on the Linux backends and the
  supervisor
- [`security.md`](security.md) — threat model, what is guaranteed, and the
  limitations that have been tested rather than assumed
- [`publishing.md`](publishing.md) — cutting a release: what a tag does, and
  how it reaches crates.io, npm and PyPI

## Development

```console
$ cargo test                    # policy, matching and CLI behaviour, any platform
$ cargo test --test enforcement # real bypass attempts, Linux only
$ cargo test --test supervisor  # install → agent.lock → enforced, Windows and macOS
$ cargo test --test immutable   # what chflags uchg does and does not do, macOS only
```

The enforcement tests need a kernel that provides at least one backend. In a
container, `--security-opt seccomp=unconfined` is usually what makes user
namespaces available; Landlock needs 5.13+ with the LSM enabled.

## License

Copyright 2026 Ralon contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE), or
<http://www.apache.org/licenses/LICENSE-2.0>.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work is licensed under the same terms, per section 5 of the
license.
