# Security model

Ralon makes a narrow promise and tries to make it exactly. This document
says what the promise is, what it is not, and which of the claims have been
tested rather than reasoned about.

## Threat model

**Defends against:** a process that runs with your privileges and tries to
modify a path the policy protects. That covers the ordinary case — an agent
editing a file it should not have touched — and the adversarial one: a
prompt-injected agent that deliberately goes after `.env`, an agent that shells
out to `sed`, `python` or `git checkout`, and any process it spawns, including
ones that outlive it.

Which processes are covered depends on the platform, and it is worth being
exact:

| | Linux (`run`) | macOS (`run`) | Windows (`run`) | Windows (`guard`) |
| --- | --- | --- | --- | --- |
| the agent and everything it spawns | yes | yes | yes | yes |
| an agent started any other way | no | no | no | **yes** |
| survives being killed | nothing to kill | nothing to kill | job object kills the command too | no — the locks go with it |

**Does not defend against:**

- **Root.** Anything that can become root outside the namespace can undo all of
  it. This is a guardrail for a tool you invited in, not a defence against an
  attacker who already has your password.
- **Processes you did not start this way** — on Linux. The policy binds the
  process tree under `ralon run`. An agent launched directly is unrestricted,
  and so is a daemon that was already running — a language server, a
  file-watcher, an editor with a remote API. If a sandboxed process can ask one
  of those to write a file, the write happens outside the sandbox. Do not run an
  IPC-reachable writer alongside an agent you do not trust. On Windows this is
  what `ralon guard` exists for: it refuses every process, so the daemon is
  covered too.
- **Killing or blocking a guard** — but not silently. On Windows a guard is a
  process, and a process running as you can terminate it, suspend it (its handles
  survive suspension, so the locks hold until it actually dies), or squat its
  claim so a fresh one cannot start. That is the same boundary that lets an agent
  run `ralon scope remove`: there is no password by design. Two things it is
  *not*. It is not a way to modify a protected path while a guard is up — the
  locks refuse that regardless. And it is not silent: `status` reports whether the
  files are actually locked, not whether a claim exists, so a killed guard reads
  as gone and the supervisor starts another. See *Lifetime* and *The record is
  not evidence* for why that distinction is load-bearing and how it was almost
  lost.
- **Reading.** Protected files stay readable, deliberately: `agent.lock`
  declares what must not *change*. A secret an agent must not read does not
  belong in the project directory.
- **Exfiltration.** Nothing here touches the network.
- **The kernel, the crates, the CPU.** A Landlock or namespace vulnerability, a
  compromised dependency, or hardware is out of scope.

## What is guaranteed

Inside `ralon run`, for every protected path, in that process and every
descendant:

| Attempt | Result |
| --- | --- |
| write, append, truncate, `cp` over it | denied |
| delete, rename away | denied |
| replace by renaming another file over it | denied |
| delete then recreate | denied |
| hard link or symlink over it | denied |
| create anything inside a protected directory | denied |
| rename or remove a directory on the way to it | denied |
| `chmod` then write | denied |
| reach the inode through a hard link made inside the sandbox | denied |
| escape by `umount`, `mount --bind`, or a nested namespace | denied |
| reach it through another process's `/proc/<pid>/root` | denied |
| read it | allowed |
| everything else in the project | unaffected |

Each row is a test in `tests/enforcement.rs`. They run a real shell inside a
real sandbox and then check the file from outside it, against every backend the
kernel offers.

## Why it cannot be undone

- A Landlock domain is one-way. There is no syscall to leave one, and it
  survives `fork` and `execve`.
- The mount namespace is locked before your command starts. Entering a second
  user namespace marks every inherited mount `MNT_LOCKED`, so `umount` fails and
  `copy_tree` refuses any bind mount that would expose what is underneath.
- `no_new_privs` is set, so a setuid binary cannot be used to climb out.
- Nothing supervises the sandbox, so there is nothing to kill. `ralon`
  *becomes* the command.

Two things fall out of the design rather than being enforced by a check:

**Hard links cannot reach a protected file.** Under the mount backend the
protected path is itself a mount point, and `link()` requires source and target
to be on the same mount — every attempt returns `EXDEV`. Under the Landlock
backend the same attempt is denied for a different reason: cross-directory links
need `REFER`, which the ancestor chain is never granted, and same-directory
links need `MakeReg` on a directory that is never granted either.

**`/proc/<pid>/root` is not a way out.** Following another process's root
requires `PTRACE_MODE_READ`, and a process in a nested user namespace does not
have it over processes in the parent one, even at the same uid. Verified: the
write returns `EPERM`.

## Known limitations

**A hard link made before the sandbox starts bypasses both backends.** A
protected file with a second name is reachable through that name: it is an
ordinary file, not bind-mounted and not carved out of the Landlock grant, and
writing it changes the protected file's contents. Verified — a write through
the second name changed `.env` from inside the sandbox. `status` and `run` warn
when a protected file has more than one link, and so does the supervisor, into
its log, at the moment it starts enforcing — which is the only notice anyone
gets, since nothing about the enforcement can prevent it. (Links created
*inside* the sandbox are still refused: see "Why it cannot be undone".)

The warning applied to Linux and macOS only until recently: the Windows
implementation returned an empty list, so the one platform whose backend is
*entirely* about holding file handles was the one that never mentioned a second
handle-able name for the same bytes. NTFS has hard links and `mklink /H` needs
no privilege. It now asks `GetFileInformationByHandle`, which is the only way to
get a link count on Windows — `std::fs::Metadata` does not carry one — and is
tested against a real second name rather than a fixture.

**A second path to the same directory bypasses both backends.** This is tested
and true: if the project is also visible at another mount point — a bind mount
made before the sandbox started, a volume mounted twice into a container, a
network share exported at two paths — writing through the other path is not
restricted. Both backends are path-based, and neither can protect a path it was
not told about. The sandboxed process cannot *create* such a mount (the mount
backend locks its namespace; the Landlock backend runs where user namespaces are
typically unavailable), so this requires the second path to already exist. If
your setup has one, protect it too or do not use it.

**Landlock alone can be defeated where user namespaces are available.** Landlock
rules apply to paths, not inodes. A process that can create its own mount
namespace can bind the project somewhere the carve-out granted, and write
through the new path. `auto` therefore prefers the mount backend, which is
available in exactly the environments where this attack is; forcing
`--backend landlock` on a machine with unprivileged user namespaces gives up a
real guarantee.

**A file another program is using cannot be locked** (Windows). A live SQLite
database, a log a dev server appends to, a state file a daemon rewrites: the
handle Ralon needs is refused because that program already holds one. `status`
warns and `run` refuses to start, rather than reporting the path as locked
while it is not. This is a policy naming the wrong thing — protect the files a
program owns, not the ones it has open.

**Only paths that exist can be protected.** A bind mount needs something to
mount. `status` and `run` warn about patterns matching nothing. The Landlock
backend is stricter here by accident of its design: it forbids creating anything
in the ancestor directories, so a missing `.env` cannot be created at all.

**The policy is read before the sandbox starts.** Nothing races it — the scan
and the mounts happen in one single-threaded process before `exec` — but a path
created after that point is not protected for the lifetime of that run. Restart
the agent after adding files that need protecting.

**Landlock's create-restriction is a functional cost, not a security one.** See
`architecture.md`. It is why `mount` is the default.

## macOS

`run` enforces through a Seatbelt profile: `agent.lock` is compiled to SBPL and
applied to this process with `sandbox_init`, which is inherited across `exec`
and by every descendant and cannot be left. That is the same property the Linux
backends have — `run` becomes the command, so there is no supervisor to kill.

Seatbelt is the only one of the three that can state the policy directly,
because SBPL has `deny`:

```text
(version 1)
(allow default)
(deny file-write* (literal "/proj/.env") (subpath "/proj/config"))
```

Two consequences follow, and both are improvements on the platforms either side
of it. Nothing outside the named paths behaves differently, so unlike Landlock
there is no create-restriction to work around. And a protected *directory*
covers entries created inside it later, so unlike the Windows locks there is no
gap needing an ACL to reach. Directories on the way to a protected path are
denied as `literal` nodes rather than `subpath` trees: that stops the directory
being renamed or removed without making its contents read-only.

Specific to this backend:

- **`sandbox_init` is deprecated** — since 10.8, with no public header. It is
  also what every sandboxed application on macOS uses, and the supported
  alternative is the App Sandbox, which is an entitlement on a signed `.app`
  bundle and not something a command-line tool can be. So this is a dependency
  on a deprecated API, named here rather than left implied. If it is ever
  removed, `run` fails loudly: the kernel's refusal is reported verbatim and
  the command is not started.
- **A rejected profile is an error, never a warning.** Nothing is applied
  partially.
- Rules name paths, so a hard link or a second path to the same file is outside
  them, exactly as on Linux. `audit.rs` reports the hard-link case.

The attack tables in `tests/enforcement.rs` run against this backend on a real
macOS kernel in CI, with `RALON_REQUIRE_BACKEND=1` so that "nothing was tested"
fails the job.

### The immutable backend, and what it is not

`ralon guard` and the supervisor cannot use Seatbelt. A profile restricts the
process it is applied to and its descendants, and both of those exist to protect
processes nobody started. They use `chflags uchg` — the user immutable flag —
instead, and this section is the whole basis on which that should be trusted.

**Ralon previously declined to implement this**, on the grounds that it is a
narrowing of the same kind as the Windows deny ACE and should not be presented as
protection. That decision is reversed. What changed is that `ralon install` needs
something a background process can impose, and on macOS this is the entire list:
Seatbelt is inherited and cannot be imposed, and Endpoint Security needs an
Apple-granted entitlement, root, and Full Disk Access — a privileged process an
agent could talk to, which is worse than the problem. So it is implemented, and
described as what it is.

What it refuses, for every process on the machine, tested in `tests/immutable.rs`:
overwrite, truncate, append, `rm`, `mv` away, `mv` over, `cat >`, `sed -i`, and
creating a new entry inside a protected directory. Every ordinary write.

What it does **not** do, each with a test that asserts the weakness so the claim
here cannot drift:

- **An agent can undo it.** `chflags nouchg` needs no privileges and is one
  command. This is a narrowing, not a sandbox, and **it is not equivalent to
  process-level sandboxing**. `run` is: a Seatbelt profile cannot be dropped,
  inspected, or lifted by the process it applies to.
- **Unprotected ancestors are not pinned, and that permits substitution.** This
  is the sharpest limitation of this backend, so it is stated as the attack it
  is. Given a policy protecting `src/deep/secret.txt` where neither `src/` nor
  `src/deep/` is protected:

  ```console
  $ mv src/deep src/moved        # allowed: src/ is not flagged
  $ mkdir -p src/deep
  $ echo whatever > src/deep/secret.txt
  ```

  The original bytes remain immutable under their new name. They are also no
  longer the bytes anything reads: every build, test run and deploy that opens
  the declared path now gets the attacker's file. "The path no longer refers to
  it" is the mild way of saying the policy has been defeated.

  **Why it is not fixed.** macOS gives one flag meaning both *this directory may
  not be renamed* and *this directory may not accept new entries*. Pinning `src/`
  would stop the project ever gaining a file in `src/`; pinning the project root
  — which every policy needs, because `agent.lock` lives there — would stop it
  gaining a file at all. Every other backend separates the two: a mount point, a
  held directory handle, and a Seatbelt `literal` node each forbid the rename
  while leaving creation alone. This one cannot, so the gap is named rather than
  closed at a price nobody agreed to.

  **What closes it.** Protect the *directory* instead of the file inside it. A
  protected directory carries the flag itself and cannot be renamed, so the
  substitution has nowhere to start. `audit.rs` detects the exposed case and
  prints exactly that advice before the guard starts, and `ralon status` repeats
  it.

  Every clause above has a test in `tests/immutable.rs`: that the substitution
  succeeds, that protecting the directory stops it, and that the warning fires
  only when the exposure is real. The corresponding attacks are held on every
  other backend by `tests/enforcement.rs` and `tests/supervisor.rs`.
- **It leaves state behind.** A supervisor that is killed cannot clear the flags,
  so they stay set. That fails *closed* — the files remain protected — and is the
  opposite failure mode from Windows, where a killed guard loses protection.
  `ralon status` reports it and `ralon guard --stop` clears it.
- **A path that cannot be flagged is reported, never skipped in silence** —
  another user's file, a read-only filesystem, a filesystem with no flags. The
  rest of the policy is still applied.

The honest summary: on macOS, `ralon run` is the guarantee and the supervisor is
a narrowing that covers the agents `run` cannot reach. Both are worth having;
they are not the same thing and this document will not call them the same thing.

## Windows

`run` enforces on Windows through exclusive share-mode handles: Ralon holds
every protected file open allowing readers and refusing writers, so any attempt
to write, delete, rename, or replace one fails with a sharing violation. The
crucial property is that this binds **processes, not agents** — the blocked
process does not have to know what Ralon is, so it covers every agent equally,
including ones with no hook support at all.

ACLs were the obvious alternative and are the wrong tool: an agent runs as the
same user, so any permission Ralon can set it can unset. A handle is not a
permission and cannot be argued with.

Verified on Windows — overwrite, append, delete, rename away, replace by copy,
replace by move, rename the parent directory, write inside a protected
directory, remove the protected tree, rewrite the policy, and clear the
read-only attribute then write. All refused; ordinary edits elsewhere
unaffected.

### New files in a protected directory

Creating an entry inside a directory opens no existing object, so no share mode
is ever consulted and no handle can refuse it. Ralon adds a deny ACE for
`Everyone` over `FILE_ADD_FILE` and `FILE_ADD_SUBDIRECTORY` while it is
running, which refuses creating a file, creating a subdirectory, copying or
moving a file in, and renaming one inside — all tested.

**This one is a narrowing, not a guarantee, and the difference is the point of
the rest of this page.** The agent runs as the same user and owns the
directory, and an owner's `WRITE_DAC` is implicit: it cannot be denied. Tested
directly — with an explicit deny ACE on `WRITE_DAC` itself, the owner still
removed it and created the file. So an agent that decides to rewrite the ACL
gets its write. What this buys is that every ordinary create is refused and the
remaining route is one an agent has to take deliberately. The handle locks are
the part that cannot be argued with; this is not, and is labelled accordingly.

The ACE is removed when Ralon exits. If Ralon is killed instead, it stays —
which fails *closed*, on a directory the policy protects anyway. `status`
reports it and `ralon guard --stop` clears it. A directory whose ACL already
names `Everyone` is left alone and reported, rather than having permissions
Ralon did not write rebuilt around it.

### A guard, and what it changes

`ralon run` protects the agent it starts. `ralon guard` protects the ones it
does not: it holds the same locks with no command to supervise, and Windows
refuses them to every process on the machine. An agent launched from an IDE, an
extension, another terminal, or installed next month is refused without knowing
Ralon exists — verified against unwrapped `cmd.exe` for overwrite, append,
delete, rename, writing a protected file, rewriting the policy, and creating a
new file in a protected directory.

That inverts the usual platform ranking, and only on this one point. Linux
enforcement is *inherited*: applied to a process before it runs, so there is
nothing left to kill, and correspondingly no way to reach out and restrict a
process you did not start. Windows enforcement is *held*: it covers every
process, and it lasts exactly as long as the process holding it. A guard can be
killed, and killing it releases the locks. `run` on Linux cannot be.

### Lifetime

**Protection lasts as long as Ralon does.** There is no inheritable restriction
to hand over, so Ralon supervises rather than `exec`ing. An agent could kill its
supervisor, so a command started by `run` is placed in a job object that dies
with Ralon — killing Ralon kills the command with it, tested. A guard has no
child to put in a job, so killing a guard leaves the agent running with the
files writable; `status` says whether one is running, which is the only
notice there can be.

That last sentence is only worth anything if `status` cannot be lied to, and for
a while it could. "Is a guard running" was answered by whether the guard's claim
existed — a named pipe under `\\.\pipe\ralon-guard-<hash>`. The hash is of the
project path and is computed in open source, so *any* process running as you
could create a pipe of that name and hold nothing else: `status` would report a
running guard over a writable file, and — worse — the supervisor would record the
project `enforced` and never start a real guard, because the check its respawn
depends on was the one being fooled. A claim is a promise; a lock is a fact.
`running` now opens `agent.lock` for writing and asks whether the *file* refuses
it. A share-mode lock cannot be faked without holding the file, and a process
holding the file that way is protecting it — so the only way to make this report
a guard is to be one. The pipe still exists, as the rendezvous `--stop` connects
to; it just no longer stands in for the thing it was meant to prove.
`tests/enforcement`-style coverage lives beside the code, in
`enforce/windows/guard.rs`: a pipe held with no locks must read as *not running*,
and a genuinely locked file must read as running.

## The supervisor

`ralon install` registers a per-user background process that starts enforcement
for any project containing an `agent.lock`, under directories the developer named
once. It introduces **no new way to stop a write**: it starts the same guard the
developer would have started by hand, so nothing about it is easier to bypass
than `ralon guard` is. What has to be examined is the discovery, not the
enforcement.

- **`agent.lock` grants nothing by existing.** Only paths inside a declared scope
  are considered, so a policy file arriving inside a downloaded archive or a
  dependency's source tree is inert. Being honoured is a permission the developer
  gives to a directory, by name, once. The check is applied to what the filesystem
  notification reports as well as to the sweep, so an event cannot introduce a
  workspace the configuration does not allow.
- **A broad scope is a convenience question, not a security one.** Scopes are
  arbitrary directories and may be as wide as a whole drive. What that permits is
  bounded by the policy format rather than by the scope: patterns are relative to
  the file that declares them and `..`, absolute paths, `~` and `!` are rejected,
  so the most a hostile `agent.lock` can achieve by being found is making *its
  own directory* read-only until someone removes it. It cannot name a path
  elsewhere on the machine, a backend, a command, or a privilege level. Adding a
  drive root is warned about because discovery gets slower, not because it opens
  a hole.
- **The policy is data, not configuration of Ralon.** It names patterns relative
  to itself and cannot select a backend, a command, a privilege level, or a path
  outside its own project — `..`, absolute paths, `~` and `!` are rejected by the
  same parser the CLI uses. There is nothing in the format for a hostile
  `agent.lock` to escalate with.
- **Nothing runs as root or administrator.** The Windows registration is a Task
  Scheduler logon task with `LeastPrivilege`; the macOS one is a LaunchAgent under
  the user's own `~/Library`. A tool that protects you from an agent should not be
  the reason a privileged process exists for an agent to talk to.
- **The supervisor runs in session 0 on Windows, and its claim is machine-wide.**
  The logon task uses the `S4U` logon type, which is what keeps a console window
  from opening at every logon — session 0 has no desktop to open one on. That put
  the supervisor in a different session from every `ralon` a person types, which
  matters because a guard's claim used to be a `Local\` named event: scoped to one
  logon session, while the share-mode locks it stood for are refused to every
  process on the machine. The claim described something narrower than what it was
  claiming. The visible result was `status` reporting `guard not running` about a
  running guard, and `pause` reporting a project released while its files stayed
  locked — a *false negative about enforcement*, which is the one direction this
  tool must never get wrong. The claim is now a named pipe under `\\.\pipe\`,
  which is one namespace for the whole machine and needs no privilege, so the
  claim's scope and the lock's scope are the same thing. Regression-tested in
  `enforce/windows/guard.rs`; verified end to end by pausing a session-0 guard
  from an ordinary terminal and confirming on disk that the file became writable
  and locked again on `resume`.
- **The supervisor protects its own binary and its own scopes.** Both live in a
  directory the user can write, because nothing here asks for administrator —
  so an agent could replace `bin/ralon.exe` and own the supervisor at the next
  logon, or delete a line from `config.yaml` and unprotect every project under
  that scope, without touching a single protected file. While a supervisor is
  running it holds both: the binary with an exclusive handle (macOS: `chflags
  uchg`, with the same limitation as everywhere else — `chflags nouchg` undoes
  it), and `config.yaml` against writers but not readers. Verified by attacking
  a running install: rename, overwrite, delete and scope-wipe are all refused
  with the files unchanged afterwards. `ralon scope add` still works — it asks
  the supervisor to stand down, writes, and starts it again; the guards keep
  holding their projects throughout, so nothing becomes writable in between.

  Two things this is **not**. It is not protection when no supervisor is
  running — these are held handles, and a machine with Ralon stopped has an
  ordinary writable state directory. And it does not stop an agent using
  Ralon's own interface: anything that can run `ralon scope remove` can remove
  a scope, because there is no password and no approval step *by design*. That
  is the same boundary that lets an agent kill a guard. What is closed is the
  silent path — editing the files directly, with nothing to notice. Every
  change made through Ralon is appended to the supervisor log with what the
  scopes were before it.

  An earlier attempt at this kept a fingerprint of `config.yaml` and reported
  mismatches. It is recorded here because it looked convincing and did not
  work: the supervisor reconciles within a second of any write to that file,
  and reconciling means adopting, so a tampered configuration was
  re-fingerprinted almost immediately and then reported as intact. A check that
  goes green a second after the attack is worse than no check.
- **The registered binary is a copy Ralon owns.** `install` copies the executable
  into the state directory and registers that path, rather than registering
  wherever the binary happened to be — which for most installs is inside a
  package manager's directory. This is not a privilege boundary; the copy sits
  somewhere the user can write, like every other place the binary could live. It
  removes two failures: a running supervisor made its own package impossible to
  uninstall on Windows, where the image of a running process cannot be deleted;
  and removing the package left the registration pointing at a path that no
  longer existed, failing at every logon in silence. `status` now names a
  registration whose binary is missing.
- **A malformed policy enforces nothing and says so.** It is not partially
  applied and does not fall back to a previous policy. Failing *closed* here
  would mean freezing a repository on the strength of a file nobody could read;
  the project is left alone, `status` exits 2 and names the line, and the
  supervisor records the failure rather than retrying it in silence. The case
  that would matter most cannot arise: an enforced workspace has its own
  `agent.lock` locked, so nothing can corrupt it while enforcement is in place.
- **The record is not evidence.** The supervisor asks the kernel whether each
  workspace is actually enforced rather than trusting `workspaces.json`. This is
  load-bearing on Windows: enforcement lives in a process, so a reboot ends all of
  it while the file still says `enforced`, and a supervisor that believed its own
  notes would come up, agree with itself, and protect nothing. The same check
  restores a guard that was killed — provided the check reads the *lock* and not a
  claim that a killed guard's replacement could be prevented from ever taking. It
  does; see *Lifetime* for the squat that made this precise. What a same-user
  process can still do is *deny* — kill the guard and squat its claim so the next
  one cannot start — and that now surfaces as a workspace the supervisor reports
  it *cannot* enforce, logged, rather than one it falsely believes it has.
- **State is per-user and outside the repository.** `agent.lock` is never written
  to. Everything the supervisor learns lives in its own state directory.

Its limits are the limits of the thing it starts. On Windows a supervisor is a
process and killing it releases the locks — `run` has nothing to kill, which is
why it remains the stronger option for an agent you launch yourself. On macOS see
*The immutable backend, and what it is not*, above.

One consequence of session 0 is worth stating plainly because it is a gap rather
than a trade: a process there has no network credentials, so a scope on a mapped
drive or a UNC path is not reachable by the supervisor and projects under it are
**not** discovered. `ralon scope add` warns when given one. `ralon guard` and
`ralon run` work there normally — they run in your session — so the answer is to
use those rather than to expect automatic discovery on a network share.

## Where there is no enforcement at all

Every platform Ralon ships for now has a backend for `run`. Linux has no *guard*
and therefore no supervisor: its restrictions are inherited by a process before
it starts, never imposed on one already running, so an agent launched any other
way is unrestricted there — which is the situation most people are actually in
until they start the agent through `ralon run`. `ralon install` fails on Linux
with that explanation rather than registering a systemd user unit, which would
start cleanly, report `active (running)`, and enforce nothing.

`ralon hook install` writes a refusal into the agent's own configuration. Be
precise about what that buys:

- It covers the agent's **file-editing tools**, and refuses before the write.
  Nine agents document a hook that can do this; the list and the exact refusal
  each one reads are in `README.md`.
- It does **not** cover a shell command the agent runs. A hook cannot tell
  which paths `sed -i` will touch, so `Bash` is deliberately not matched rather
  than matched badly.
- It lives in a file inside the project. An agent that can edit it can remove
  it — unless `agent.lock` protects that file too, which on a platform with no
  enforcement is itself only a hook away from being edited.
- It depends on the agent honouring its own documented contract. That is a
  different kind of claim from "the kernel refused the write", and the two are
  never listed as if they were the same thing.

So it is a courtesy, not a guarantee. The recommendation everywhere is to start
the agent with `ralon run`, where the kernel does the refusing — and on Windows,
`ralon guard`, which does not care how the agent was started.

## Verifying it yourself

```console
$ cargo test --test enforcement        # every attack, every available backend
$ ralon status                    # what this kernel can actually enforce
$ ralon run --dry-run -- claude   # exactly what will be locked
```

Do not take the tests' word for it either — check by hand:

```console
$ ralon run -- sh
$ echo x > .env            # EROFS or EACCES
$ rm .env                  # denied
$ echo x > src/App.tsx     # fine
```

If `status` reports no available backend, `run` refuses to start the command
rather than running it unprotected. A failure to enforce is never silent.

## Reporting a vulnerability

A bypass is anything that modifies a protected path from inside
`ralon run` without root, other than the limitations listed above. Please
report it privately — email the maintainers or open a GitHub security advisory —
with the policy, the command, and the kernel version (`uname -r`) and backend
(`ralon status`). A failing test case in the style of
`tests/enforcement.rs` is the most useful possible report.

## Hardening still on the table

- Warn when the project root is reachable through a second mount, by reading
  `/proc/self/mountinfo`.
- A seccomp filter denying `mount`, `umount2`, `unshare` and `setns` in the
  sandboxed process, as defence in depth behind the locked namespace.
- Applying both backends at once for callers who want the Landlock guarantees
  on top of the mount ones and can live with the create-restriction.
