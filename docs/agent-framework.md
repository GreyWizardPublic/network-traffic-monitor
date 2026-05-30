# Multi-Agent Collaboration Framework

Generic rules for projects where multiple Claude Code sessions — running on
different operating systems — collaborate on the same git repository. Each
session is called an **agent** and owns a distinct code domain.

Copy this file into any new multi-agent project and pair it with a
project-specific `docs/project-rules.md` that supplies the concrete facts
(agent names, owned paths, version files, build commands, etc.).

---

## 1. Parallel workflow — the golden rule

Each agent owns a code domain exclusively and works on its own feature branch.
Changes may land to `main` without waiting for the other agents. The two hard
constraints are **protocol changes** (§6) and **cross-domain work** (§4).

---

## 2. Agent identification convention

At the start of every session, the agent detects its own role by inspecting its
local environment (OS, installed toolchain, presence of sentinel files, etc.).
The detection logic and the concrete role-to-domain mapping are defined in
`docs/project-rules.md` for each project.

**Template: environment → role mapping**

| Environment | Detection command / condition | Role | Branch prefix |
|---|---|---|---|
| *(fill in)* | *(fill in)* | *(fill in)* | *(fill in)* |

Concrete values for this project live in `docs/project-rules.md §2`.

---

## 3. Branch & merge workflow

All agents follow these steps regardless of role or OS.

### 3.1 Start a feature branch

Always branch from the latest `main` before any new unit of work:

```bash
git checkout main && git pull
git checkout -b <prefix>/<short-description>
```

Replace `<prefix>` with the project-defined prefix for your agent role
(see `docs/project-rules.md §2`).

### 3.2 Commit only files inside your code domain

Never touch another agent's files directly. If a cross-domain change is needed,
use the handoff workflow (§4).

**Shared project files — editable by any agent without a handoff**

The files below are project-wide and are not owned exclusively by any agent.
Each agent may edit them directly on its own prefixed branch for content that
falls within its domain:

| File | Why it's shared |
|---|---|
| `CLAUDE.md` | Required reading entry point. |
| `docs/agent-framework.md` | Each agent may add or update its own per-OS section (§8). |
| `docs/project-rules.md` | Each agent owns its own role sub-section (paths, version files, build commands). |
| `.gitignore` | OS- and build-specific ignore patterns. |

Open a normal `<prefix>/<description>` PR and merge independently.

A cross-agent handoff **is** still required when an agent needs to correct or
extend *another agent's existing sub-section* in any of these files.

### 3.3 Open a PR

Open a PR targeting `main` when the work is ready. PR description must include:
- What changed and why.
- Build instructions applicable to your domain.
- A test checklist confirming the test quality gate (§3.4) was met.

### 3.4 Test quality gate — required before merging any feature branch

**a. Add tests for every new feature.** Any new pure-logic function (parser,
classifier, helper) must have unit tests before the PR is opened. If the
function lives in a `.cpp` file and cannot be included by the test binary,
move it to a header as `inline`.

**b. Remove obsolete tests.** If a refactor deletes or renames a function,
remove tests that exercised the old interface in the same commit. Keeping
dead tests is a maintenance hazard.

**c. Run the full test suite and report results in the PR description.** All
tests must show `N passed, 0 failed`.

**d. If any test fails**, do not fix it silently. Document the failure in the
PR description with the test name, observed output, and root-cause analysis.
Tag it **⚠️ FAILING TEST — human review required** and wait for approval
before landing a fix.

### 3.5 Merge the PR independently

No sign-off from other agents is required unless the change touches a shared
protocol (§6).

### 3.6 Delete the feature branch after merge

Delete both local and remote:

```bash
git branch -d <branch>
git push origin --delete <branch>
```

Then verify the branch is gone from the remote:

```bash
git ls-remote --heads origin <prefix>/
```

If the branch is still listed after the delete command, investigate before
moving on — a failed push means the remote is in an inconsistent state.

### 3.7 Start-of-session checklist

Do the following in order before starting any new work:

**a. Check for open PRs and GitHub Issues addressed to your agent** (see §4)
and address them.

**b. Audit your own stale remote branches:**

```bash
git fetch --prune
git ls-remote --heads origin <prefix>/
```

Any branch whose PR is already merged (closed) must be deleted immediately.

**c. Audit stale handoff branches you resolved.** Any handoff PR you closed
in a previous session may have left its branch behind. Check for handoff
branches from *other* agents that targeted your prefix and have a closed PR:

```bash
git ls-remote --heads origin <prefix-A>/handoff/
git ls-remote --heads origin <prefix-B>/handoff/
# … repeat for each other agent's prefix
```

For each branch listed, check whether its PR is already closed:

```bash
gh pr list --state closed --head <branch>
```

If so, delete the branch immediately.

---

## 4. Cross-agent handoff protocol

Use a handoff when one agent needs another to change **code in the receiving
agent's domain**. Do not use it for shared-file additions (§3.2).

### 4.1 Opening a handoff PR

The requesting agent:
1. Creates a branch `<receiving-prefix>/handoff/<short-description>`.
2. Adds any starter code or stubs.
3. Opens a PR targeting `main` with a body following this template:

```
Title: [RECEIVING AGENT NAME] <short description>

## Problem
<what is wrong or missing>

## Required change
<specific files, functions, or behaviour that needs to change>

## Context
<why this is needed; relevant error messages or test failures>

## Starter diff (optional)
<draft of the change so the receiving agent can review, complete, and merge>
```

### 4.2 Receiving a handoff PR

The receiving agent:
1. Implements or completes the work on its own branch (`<my-prefix>/<desc>`).
2. Merges its own PR to `main`.
3. Closes the handoff PR with a comment summarising what was done.
4. **Immediately deletes the handoff branch** — even though the branch carries
   the requesting agent's prefix:
   ```bash
   git push origin --delete <requesting-prefix>/handoff/<desc>
   ```
   GitHub's auto-delete-on-merge only fires when a PR is *merged*; closing a
   PR manually leaves the branch behind. The requesting agent may never
   re-visit the closed PR, so the **receiving agent is solely responsible**
   for this cleanup.
5. The requesting agent then rebases its active branch on the updated `main`.

**Rule: the agent that closes a handoff PR owns the handoff branch deletion,
regardless of which agent's prefix the branch carries.**

---

## 5. Versioning scheme

Each module is versioned **independently**. A change in one module does not
require a version bump in another unless a shared protocol also changes (§6).

### 5.1 Format: `MAJOR.MINOR.PATCH.REVISION`

Every change to a module's code — however small — must bump exactly one
component. REVISION is the floor.

| Component | When to bump | What resets to 0 |
|---|---|---|
| **MAJOR** | Breaking protocol or auth change | MINOR, PATCH, REVISION |
| **MINOR** | New backward-compatible feature | PATCH, REVISION |
| **PATCH** | Bug fix that changes observable behaviour | REVISION |
| **REVISION** | Any other change: refactor, log message, config tweak, comment, dependency update | — (nothing resets) |

**Decision guide** — when in doubt, use the highest applicable level:
- Does it break the wire protocol or auth? → **MAJOR**
- Does it add something new the other side can use? → **MINOR**
- Does it fix wrong behaviour? → **PATCH**
- Everything else → **REVISION**

**Examples:**

```
1.18.0.0  →  fix typo in log message           →  1.18.0.1   (REVISION)
1.18.0.1  →  fix bug in overhead classification →  1.18.1.0   (PATCH, REVISION resets)
1.18.1.0  →  add /api/clients endpoint          →  1.19.0.0   (MINOR, PATCH+REVISION reset)
1.19.0.0  →  bump wire protocol version         →  2.0.0.0    (MAJOR, all reset)
```

### 5.2 Rules

1. **Every commit that touches module code bumps exactly one component.**
   There is no such thing as a change too small to version.
2. **Update the version file in the same commit as the change** — never in a
   separate follow-up commit.
3. **One component, one step forward.** Each commit increments exactly one
   component by exactly 1. Also choose the *lowest* applicable level: a bug
   fix is PATCH even if large; bumping MINOR for a bug fix overcounts and is
   not allowed.
4. **Lower components reset when a higher one bumps.**
   `1.2.3.4 + PATCH → 1.2.4.0` (not `1.2.4.4`). `1.2.3.4 + MINOR → 1.3.0.0`.
5. **Always read the current version from the module's version file** before
   deciding the next number — do not rely on memory or git log alone.

The concrete module list and their version files are in `docs/project-rules.md §3`.

---

## 6. Protocol governance

When multiple modules communicate over a versioned protocol, the protocol
version is a shared invariant: all modules that speak the protocol must stay
in sync.

### 6.1 Protocol changes land directly on `main` — never on a feature branch

All agents may have active feature branches at any time. A protocol change on a
feature branch would force other agents to rebase mid-flight and risks merge
conflicts in shared headers. Instead: commit protocol changes (doc update +
constant bump + all sides of the implementation) directly to `main`, then **all
agents** rebase their active feature branches immediately:

```bash
git fetch origin
git rebase origin/main
```

### 6.2 Rules

1. **Update the protocol doc before the commit that changes either side.**
   Never change a message format, field, or endpoint without updating the spec
   doc first.
2. **Bump the protocol version constant** when the change classification in
   the doc requires it.
3. **Protocols are independent.** A change to protocol A does not require a
   version bump in protocol B — unless the same commit touches both.
4. **When a protocol bumps, bump every lockstep module** (all modules that
   speak the protocol receive at least a MINOR bump in the same commit; a
   breaking change requires MAJOR for all of them).

The concrete protocols, their constants, and their lockstep module tables are
in `docs/project-rules.md §4`.

---

## 7. Production deployment — push policy

> **Agents MUST NEVER call any flag or argument that mutates a production
> system (`--confirm`, `--push`, `--deploy`, or equivalent) on their own
> initiative. That flag may only be supplied when a human explicitly instructs
> the action in the same conversation turn. Dry-run invocations (without the
> destructive flag) are always permitted for pre-flight validation.**

This rule applies regardless of how confident the agent is that the action is
correct. The cost of waiting for human confirmation is low; the cost of an
unintended production change can be very high.

The specific push scripts, endpoints, and prerequisites for this project are
in `docs/project-rules.md §10` and `§11`.

---

## 8. Per-OS agent conventions

After an agent identifies its role (§2), it adopts the shell idioms and build
conventions for its operating system. The sub-sections below cover shell &
build idioms only — project-specific toolchains, owned paths, and build
commands are in `docs/project-rules.md`.

### 8a. Linux agent (bash)

| Task | Convention |
|---|---|
| Native shell | `bash` |
| Run a local script | `./script.sh` |
| Chain (stop on error) | `cmd1 && cmd2` |
| Read env variable | `$VAR` |
| Home directory | `$HOME` |
| Parallel build jobs | `-j$(nproc)` |
| Path separator | `/` |
| Script extension | `.sh` |

### 8b. macOS agent (zsh / bash)

| Task | Convention |
|---|---|
| Native shell | `zsh` (default) or `bash` |
| Run a local script | `./script.sh` |
| Chain (stop on error) | `cmd1 && cmd2` |
| Read env variable | `$VAR` |
| Home directory | `$HOME` |
| Parallel build jobs | `-j$(sysctl -n hw.logicalcpu)` |
| Path separator | `/` |
| Script extension | `.sh` |

### 8c. Windows agent (PowerShell)

| Task | Convention |
|---|---|
| Native shell | `powershell` / `pwsh` |
| Run a local script | `.\script.ps1` |
| Chain (stop on error) | `cmd1; if ($LASTEXITCODE -ne 0) { exit 1 }` |
| Read env variable | `$env:VAR` |
| Home directory | `$env:USERPROFILE` |
| Parallel build jobs | `-j $env:NUMBER_OF_PROCESSORS` |
| Path separator | `\` (CMake, git, and gh also accept `/` — prefer `/` in shared or documented commands) |
| Script extension | `.ps1` |

---

## 9. Cross-shell quick reference

The table below summarises §8 for side-by-side comparison.

| Task | Linux · **bash** | macOS · **zsh/bash** | Windows · **PowerShell** |
|---|---|---|---|
| Native shell | `bash` | `zsh` | `powershell` / `pwsh` |
| Run a local script | `./script.sh` | `./script.sh` | `.\script.ps1` |
| Chain (stop on error) | `cmd1 && cmd2` | `cmd1 && cmd2` | `cmd1; if ($LASTEXITCODE -ne 0) { exit 1 }` |
| Read env variable | `$VAR` | `$VAR` | `$env:VAR` |
| Home directory | `$HOME` | `$HOME` | `$env:USERPROFILE` |
| Parallel build jobs | `-j$(nproc)` | `-j$(sysctl -n hw.logicalcpu)` | `-j $env:NUMBER_OF_PROCESSORS` |
| Path separator | `/` | `/` | `\` (CMake/git/gh accept `/`) |

---

## 10. Git & gh commands (same on all platforms)

The commands below work unchanged in bash, zsh, and PowerShell.

```bash
# Branch hygiene (§3.6 + §3.7b)
git fetch --prune
git ls-remote --heads origin <prefix>/
git branch -d <branch>
git push origin --delete <branch>
git push origin --delete b1 b2 b3       # delete several at once

# PR / issue inspection via gh CLI
gh pr list --state open
gh pr list --state closed --limit 20
gh issue list --state open
gh pr view <number>
gh issue view <number>

# Rebase on latest main before opening a PR
git fetch origin
git rebase origin/main

# Amend last commit (before push)
git commit --amend --no-edit
```

> **Windows note:** PowerShell uses `\` for file paths in most contexts,
> but CMake, `git`, and `gh` all accept forward slashes — prefer `/` in
> any command that is shared or documented.
