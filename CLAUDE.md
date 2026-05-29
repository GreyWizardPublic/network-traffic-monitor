# network-traffic-monitor

## Agent Roles

Three Claude Code agents work **in parallel and independently** on this project,
each on its own feature branch. Each agent detects its own role from the OS at
the start of every session — no manual configuration needed.

### Environment detection

Run the appropriate command for your platform to identify your role:

**On Linux** — run `uname -s` and check `/etc/arch-release`:
```bash
uname -s                        # must return "Linux"
[ -f /etc/arch-release ] && echo "Arch Linux" || echo "other Linux"
```

**On macOS** — run `uname -s`:
```bash
uname -s                        # returns "Darwin"
```

**On Windows** — run in PowerShell:
```powershell
$env:OS                         # returns "Windows_NT"
```

| Environment | Detection | Role | Code ownership |
|---|---|---|---|
| Arch Linux | `uname -s` = `Linux` **and** `/etc/arch-release` exists | **Arch Linux Agent** | `src/` server + Linux client · shared headers · CMake (Linux) · `docs/` · config files · Linux/server deployment guides |
| macOS | `uname -s` = `Darwin` | **Swift Agent** | `ios/` · XcodeGen · Swift/iOS code |
| Windows | `$env:OS` = `Windows_NT` | **Windows Agent** | `src/` Windows-specific client code · `cmake/toolchain-mingw64.cmake` · Windows CMake config · Windows deployment guide · Npcap/WinSock integration |

---

### Parallel workflow — the golden rule

Each agent owns its code domain exclusively and works on its own feature branch.
Changes may land to `main` without waiting for the other agents. The two hard
constraints are **protocol changes** (see [Protocol Governance](#protocol-governance))
and **cross-agent work** (see [Cross-agent handoff](#cross-agent-handoff)).

---

### Branch & merge workflow (all agents follow this)

1. **Start a feature branch** from the latest `main` before any new unit of work:
   ```
   git checkout main && git pull
   git checkout -b <agent-prefix>/<short-description>
   ```
   Use prefix `linux/` for Arch Linux Agent branches, `ios/` for Swift Agent
   branches, `win/` for Windows Agent branches.

2. **Commit only files inside your code domain.** Never touch another agent's
   files directly. If a cross-domain change is needed, use the PR handoff
   workflow (see [Cross-agent handoff](#cross-agent-handoff) below).

3. **Open a PR** targeting `main` when the work is ready. PR description must
   include build instructions and a test checklist appropriate to the domain.

4. **Test quality gate — required before merging any feature branch:**

   a. **Add tests for every new feature.** Any new pure-logic function (parser,
      classifier, helper) must have unit tests before the PR is opened. If the
      function lives in a `.cpp` file and cannot be included by the test binary,
      move it to a header as `inline` (see `parseDataLine` in
      `proto_client_server.hpp` as the canonical example).

   b. **Remove obsolete tests.** If a refactor deletes or renames a function,
      remove tests that exercised the old interface in the same commit. Keeping
      dead tests that silently pass (or worse, no longer compile) is a
      maintenance hazard.

   c. **Run the full test suite and report results in the PR description.**
      For Arch Linux / Linux Agent: `./build-linux/ntm-tests` must show
      `N passed, 0 failed`. For Windows Agent: `ntm-tests-windows.exe` must
      show the same. For Swift Agent: Xcode test target must pass.

   d. **If any test fails**, do not fix it silently. Document the failure in the
      PR description with the test name, observed output, and your root-cause
      analysis. Tag it **⚠️ FAILING TEST — human review required** and wait for
      approval before landing a fix.

5. **Merge the PR independently** — no sign-off from other agents is required
   unless the change touches a shared protocol (see Protocol Governance).

6. **Delete the feature branch** after merge, both local and remote:
   ```
   git branch -d <branch>
   git push origin --delete <branch>
   ```
   Then **verify the branch is gone from GitHub** by listing remote branches
   for your prefix and confirming the deleted branch no longer appears:
   ```
   git ls-remote --heads origin <agent-prefix>/
   ```
   If the branch is still listed after the delete command, investigate before
   moving on — a failed push (network error, permission issue, or wrong branch
   name) means the remote is in an inconsistent state.

7. **At the start of each session**, do the following in order before starting
   new work:

   a. **Check for open PRs and GitHub Issues** addressed to your agent (see
      Cross-agent handoff below) and address them.

   b. **Audit your own stale remote branches.** Run:
      ```
      git fetch --prune
      git ls-remote --heads origin <agent-prefix>/
      ```
      Any branch whose PR is already merged (closed) must be deleted immediately.
      Cross-reference with the closed PR list if you are unsure whether a branch
      has been merged. Do not leave merged branches accumulating on the remote.

   c. **Audit stale handoff branches you resolved.** Any handoff PR you closed
      in a previous session may have left its branch behind (see Handoff workflow
      step 2 above). Check for handoff branches from *other* agents that targeted
      your prefix and have a closed PR:
      ```
      git ls-remote --heads origin linux/handoff/
      git ls-remote --heads origin ios/handoff/
      git ls-remote --heads origin win/handoff/
      ```
      For each branch listed, check whether its PR is already closed (`gh pr list
      --state closed --head <branch>`). If so, delete the branch immediately.

---

### Arch Linux Agent

**Owns:** C++ server code, Linux client code, and all shared/protocol headers in
`src/`; CMake build system (Linux targets); `docs/`; config file examples;
Linux and server deployment guides; wire-protocol and API-protocol specs.

**Responsibilities:**
- Writes and maintains all C++ code for `ntm-server` and `ntm-client` (Linux).
- Maintains shared headers used by all C++ targets (e.g. `proto_client_server.hpp`).
- Writes documentation, config examples, and Linux/server deployment guides.
- Builds the Linux server and Linux client binaries (see [Linux build](#linux-client--server) below).
- **Does not** build the Windows client — the Windows Agent owns that.
- **Does not** run XcodeGen, Xcode builds, or on-device tests.
- **Does not** write Swift code — use PR handoff instead (see below).

---

### Swift Agent (macOS)

**Owns:** all Swift/iOS code (`ios/NTMDashboard/`, `ios/NTMClient/`), XcodeGen
project files (`ios/project.yml`, per-app `project.yml`), and any future macOS
native code.

**Responsibilities:**
- Writes and maintains all Swift code for iOS apps (NTMDashboard, NTMClient).
- Applies iOS-side protocol lockstep changes (e.g. bumping `supportedApiVersion`,
  adding new model fields) when a protocol version lands on `main`.
- Runs XcodeGen (`xcodegen generate`) and builds in Xcode (⌘B).
- Runs on-device and simulator tests; handles App Store / TestFlight publishing.
- **Does not** write C++ code — use PR handoff instead (see below).

---

### Windows Agent

**Owns:** all Windows-specific C++ client code in `src/` (files conditionally
compiled for Windows, `#ifdef _WIN32` blocks, and any `*_windows*`-named files);
`cmake/toolchain-mingw64.cmake`; Windows-specific CMake variables and targets;
`CLIENT_DEPLOYMENT.md` Windows sections; Npcap SDK and WinSock integration.

**Responsibilities:**
- Writes and maintains all Windows-specific code for `ntm-client` (Windows).
- Builds the Windows client natively on Windows (see [Windows build](#windows-client-native-windows) below).
- Maintains the Windows toolchain file and Windows CMake configuration.
- Writes and updates Windows deployment documentation.
- Manages Npcap SDK, WinSock2, and any other Windows-only dependencies.
- Applies Windows-side protocol lockstep changes when a protocol version lands on `main`.
- **Does not** build the Linux server or Linux client — the Arch Linux Agent owns that.
- **Does not** write Swift code — use PR handoff instead (see below).

---

## Native Shell Reference

**All pure `git` and `gh` CLI commands are identical across platforms.** Only
the surrounding shell syntax differs. Use your agent's column below — do not
guess or copy commands from another agent's column.

| Task | Arch Linux Agent · **bash** | Swift Agent · **zsh/bash** | Windows Agent · **PowerShell** |
|---|---|---|---|
| **Native shell** | `bash` | `zsh` (default) or `bash` | `powershell` / `pwsh` |
| **Run a local script** | `./script.sh` | `./script.sh` | `.\script.ps1` |
| **Chain (stop on error)** | `cmd1 && cmd2` | `cmd1 && cmd2` | `cmd1; if ($LASTEXITCODE -ne 0) { exit 1 }` |
| **Read env variable** | `$VAR` | `$VAR` | `$env:VAR` |
| **Parallel build jobs** | `-j$(nproc)` | `-j$(sysctl -n hw.logicalcpu)` | `-j $env:NUMBER_OF_PROCESSORS` |
| **Path separator** | `/` | `/` | `\` (CMake accepts `/` too) |
| **Home directory** | `$HOME` | `$HOME` | `$env:USERPROFILE` |

### Git & gh commands (same on all platforms)

The commands below work unchanged in bash, zsh, and PowerShell — copy them
verbatim regardless of which agent you are.

```bash
# Branch hygiene (step 6 + step 7b of the workflow)
git fetch --prune
git ls-remote --heads origin <agent-prefix>/   # linux/ · ios/ · win/
git branch -d <branch>
git push origin --delete <branch>
git push origin --delete b1 b2 b3              # delete several at once

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

> **Windows Agent note:** PowerShell uses `\` for file paths in most
> contexts, but CMake, `git`, and `gh` all accept forward slashes — prefer
> `/` in any command that is shared or documented.

---

### Cross-agent handoff

When one agent needs another to make a change, it opens a **PR** (not just an
issue) that contains the required scaffolding or stub, targeting a dedicated
handoff branch named `<receiving-agent-prefix>/handoff/<short-description>`.
The PR body follows this structure:

```
Title: [WINDOWS AGENT] <short description>   ← or [LINUX AGENT] / [SWIFT AGENT]

## Problem
<what is wrong or missing>

## Required change
<specific files, functions, or behaviour that needs to change>

## Context
<why this is needed; relevant error messages or test failures>

## Starter diff (optional)
<if the requesting agent has already drafted the change, include it here
 so the receiving agent can review, complete, and merge>
```

**Handoff workflow:**

1. Requesting agent creates a feature branch `<receiving-agent-prefix>/handoff/<desc>`, adds
   any starter code or stubs, and opens a PR targeting `main`.
2. Receiving agent picks up the PR, implements or completes the work on its own
   branch (`<my-prefix>/<desc>`), merges its own PR to `main`, then closes the
   handoff PR with a comment summarising what was done, and **immediately deletes
   the handoff branch** — even though the branch carries the requesting agent's
   prefix:
   ```
   git push origin --delete <requesting-prefix>/handoff/<desc>
   ```
   GitHub's auto-delete-on-merge only fires when a PR is *merged*; closing a PR
   manually leaves the branch behind. The requesting agent may never re-visit the
   closed PR, so the **receiving agent is solely responsible** for this cleanup.
3. Requesting agent rebases its active branch on the updated `main`.

**Rule: the agent that closes a handoff PR owns the handoff branch deletion,
regardless of which agent's prefix the branch carries.**

---

## Versioning

Each module is versioned **independently**. A change in one module does not
require a version bump in another unless a shared protocol also changes (see
Protocol Governance below).

### Module version files

| Module | Version file | Constant |
|---|---|---|
| `ntm-server` | `src/server_version.hpp` | `kServerVersion` |
| `ntm-client` (Linux / Windows) | `src/client_version.hpp` | `kClientVersion` |
| NTMClient (iOS) | `ios/NTMClient/Shared/ClientVersion.swift` | `kClientVersion` |
| NTMDashboard (iOS) | `ios/project.yml` → `MARKETING_VERSION` | App Store version |

### Format: `MAJOR.MINOR.PATCH.REVISION`

Every change to a module's code — however small — must bump exactly one
component. REVISION is the floor: if a change does not clearly qualify as
PATCH, MINOR, or MAJOR, it is always REVISION.

| Component | When to bump | What resets to 0 |
|---|---|---|
| **MAJOR** | Breaking wire-protocol or auth change | MINOR, PATCH, REVISION |
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
1.19.0.0  →  bump kWireProtoVersion             →  2.0.0.0    (MAJOR, all reset)
```

### Rules

1. **Every commit that touches module code bumps exactly one component.**
   There is no such thing as a change too small to version.
2. **Update the version file in the same commit as the change** — never in a
   separate follow-up commit.
3. **One component, one step forward.** Each commit increments exactly one component by exactly 1 — `1.0.0.0 → 1.0.0.1` is correct, `1.0.0.0 → 1.0.0.3` (skipping values) is not. Also choose the *lowest* applicable level: a bug fix is PATCH even if large; bumping MINOR for a bug fix overcounts and is not allowed.
4. **Lower components reset when a higher one bumps.**
   1.2.3.4 + PATCH → 1.2.4.0 (not 1.2.4.4). 1.2.3.4 + MINOR → 1.3.0.0.
5. Always read the current version from the module's version file before deciding
   the next number — do not rely on memory or git log alone.

---

## Protocol Governance

Two protocol documents in `docs/` are the authoritative specifications:

| Document | Covers |
|---|---|
| `docs/wire-protocol.md` | ntm-client ↔ ntm-server TCP ingestion channel |
| `docs/api-protocol.md` | ntm-server ↔ dashboard clients HTTPS API |

Both protocol version constants live in `src/proto_client_server.hpp`:

| Constant | Current value | Protocol |
|---|---|---|
| `kWireProtoVersion` | `2` | Wire (data-phase line format) |
| `kApiVersion` | `11` | HTTPS API (endpoint schemas) |

### Protocol lockstep rule

When a protocol version bumps, **every module listed below must receive at
least a MINOR bump in the same commit**. A breaking change requires MAJOR for
all of them.

| Protocol | Lockstep modules | Responsible agents |
|---|---|---|
| Wire (`kWireProtoVersion`) | `ntm-server`, `ntm-client` (Linux), `ntm-client` (Windows), `NTMClient` (iOS) | Arch Linux Agent · Windows Agent · Swift Agent |
| API (`kApiVersion`) | `ntm-server`, `NTMDashboard` (iOS), embedded web dashboard | Arch Linux Agent · Swift Agent |

### Rules

1. **Protocol changes land directly on `main` — never on a feature branch.**
   All three agents may have active feature branches at any time. A protocol change on a
   feature branch would force other agents to rebase mid-flight and risks merge
   conflicts in shared headers. Instead: commit protocol changes (doc update +
   constant bump + all sides of the implementation) directly to `main`, then **all
   agents** rebase their active feature branches immediately:
   ```
   git fetch origin
   git rebase origin/main
   ```
2. **Update the relevant protocol doc before the commit that changes either side.**
   Never change a message format, field, or endpoint without updating the doc first.
3. **Bump the protocol version constant** (`kWireProtoVersion` or `kApiVersion`) when
   the change classification in the doc requires it.
4. **Both protocols are independent.** A wire-protocol change does not require an
   API version bump, and vice versa — unless the same commit touches both sides.
5. **When a protocol bumps, bump every lockstep module** per the table above.

---

## Client Configuration Key Parity

All ntm-client configuration keys are parsed by the single shared file
`src/client_config_parse.hpp` and stored in `src/client_types.hpp::ClientConfig`.
Both Linux and Windows clients `#include` these files without any platform-specific
branches, ensuring they always accept an identical set of keys.

### Rules

1. **All configuration keys MUST be added to `src/client_config_parse.hpp` exclusively —
   never in platform-specific files** — so that Linux and Windows clients always accept
   an identical set of configuration keys.

2. **All config keys must have identical runtime behaviour on all platforms.**
   Intentional platform exceptions (e.g. a feature not yet implemented on one platform)
   require:
   - Explicit documentation in `CLIENT_DEPLOYMENT.md` (noting the limitation and which
     platforms are affected).
   - A cross-agent handoff PR to the owning agent to resolve the gap before the next
     MINOR release of ntm-client.

3. **All config fields reported in H-lines (`cfg_*` fields) must reflect the actual
   runtime value on both platforms.** If a field's behaviour differs between platforms,
   the H-line must accurately reflect the effective value (e.g. `cfg_compress=0` on a
   platform where compression is disabled) so the admin dashboard shows the true state.

---

## Shared Client Sources — Cross-Platform Rebuild Rule

The following files are compiled into **both** the Linux and Windows `ntm-client` binaries
(the `NTM_CLIENT_COMMON_SOURCES` list in `CMakeLists.txt`, plus the shared version header):

```
src/client_main.cpp
src/client_core.cpp
src/client_impl.cpp
src/client_transport_tcptls.cpp
src/client_transport_websocket.cpp
src/updater.cpp
src/client_version.hpp          (version constant and platform identifier)
src/client_config_parse.hpp     (config parsing — see Client Configuration Key Parity)
src/client_types.hpp            (ClientConfig struct)
```

### Rule

**Any commit that modifies a shared client source file listed above MUST be followed
by a cross-agent handoff PR to the other client agent(s) to rebuild and push their
binary.** Specifically:

- **Arch Linux Agent** modifies a shared file → open a `[WINDOWS AGENT]` handoff PR
  asking the Windows Agent to rebuild `ntm-client-windows-amd64-<version>.exe` and push
  it to the server's `update_dir` via `push-client.sh --confirm`.

- **Windows Agent** modifies a shared file → open a `[LINUX AGENT]` handoff PR
  asking the Arch Linux Agent to rebuild `ntm-client-linux-amd64-<version>` and push it.

**Why this matters:** Clients on both platforms auto-update from the same `update_dir`.
If only one platform ships a bug fix or feature, the other platform's users are left on
broken or outdated code indefinitely. Both binaries must ship together.

The handoff PR must include:
- The specific version to build (`ntm-client X.Y.Z.R`)
- A one-line summary of what changed and why
- A request to push with `push-client.sh --confirm` once built and tested

---

## Apple Distribution cert reference (iOS)

The signing identity used for all NTMDashboard TestFlight and App Store builds.
The public cert is committed under `ios/certs/`; the matching private key lives
only in the Mac's login keychain (never in the repo).

| Field | Value |
|---|---|
| Identity name (CN) | `Apple Distribution: Dong Xue (W65LG3MSG6)` |
| Team ID | `W65LG3MSG6` |
| SHA-1 fingerprint | `A40BD2CA12210ACDD8FE89E199F62E895F0B6914` |
| Valid through | 2027-05-29 |
| Repo path | `ios/certs/AppleDistribution-W65LG3MSG6.cer` |

**Verify the correct cert is loaded before archiving:**

```bash
security find-identity -p codesigning -v | grep W65LG3MSG6
# Expected line:
#   N) A40BD2CA12210ACDD8FE89E199F62E895F0B6914 "Apple Distribution: Dong Xue (W65LG3MSG6)"
```

If the line is missing, the private key is not in keychain. Import from a `.p12`
export of the original signing Mac — do **not** commit the `.p12`.

**Other identities on the system to avoid for Release builds:**

| Identity | Why to avoid |
|---|---|
| `Apple Development: Dong Xue (2F447K4U9Z)` | Personal/free team — team ID `2F447K4U9Z` does not match. Automatic signing may pick this if the Distribution cert is missing. |
| `iPhone Distribution: Dong Xue (W65LG3MSG6)` | Legacy naming for the same team. `project.yml` pins the modern "Apple Distribution" name; use that for consistency. |

**Publishing workflow:**

```bash
# 1. Archive + export IPA (checks cert, runs xcodegen, verifies signing)
./ios/scripts/archive-app.sh

# 2. Upload to TestFlight (reads .p8 from Keychain, wipes after upload)
# ASC_KEY_ID and ASC_ISSUER_ID are in App Store Connect → Users and Access →
# Integrations. Never commit these values — pass as env vars only.
ASC_KEY_ID=<your-key-id> ASC_ISSUER_ID=<issuer-uuid> \
./ios/scripts/upload-testflight.sh
```

Never upload to TestFlight or App Store without explicit human instruction in
the current conversation turn.

---

## Demo Server

Port 12345 serves mock `/api/summary` data for App Store review (no auth, iOS only).

**Consistency rule**: Any change to the `/api/summary` JSON schema (new field, renamed field,
removed field, changed type) **must** be reflected in `buildDemoSummaryJson()` in
`src/web_dashboard.cpp` in the same commit. The mock data must mirror the real schema exactly.

---

## C++ Build

Each agent builds only its own platform binaries. The output filenames embed the
platform and version (e.g. `ntm-client-linux-amd64-1.14.1.0`) and match the
auto-update naming convention exactly — they can be dropped directly into
`update_dir` on the server without renaming.

### Stale binary cleanup (required on every version bump)

Because the version is baked into the filename, a version bump produces a
**new filename** while the old binary stays in the build directory.
**Always delete old versioned binaries before or after building a new version**
to avoid deploying the wrong file by mistake.

```bash
# Linux — remove old client binaries before building the new one
rm -f build-linux/ntm-client-linux-amd64-*

# Linux — remove old server binaries before building the new one
rm -f build-linux/ntm-server-linux-amd64-*

# Windows — remove old client binaries before building the new one
Remove-Item build-windows\ntm-client-windows-amd64-*.exe -ErrorAction SilentlyContinue
```

### Binary signing (all platforms)

Every ntm-server and ntm-client binary is **ML-DSA-65 signed at build time** as a
mandatory POST_BUILD step. An unsigned binary is never produced — if the private
key (`~/.ntm/privatebuildkey.secret`) is absent the build fails immediately.

| Script | Signs |
|---|---|
| `scripts/sign-server.sh` | ntm-server (called by CMake POST_BUILD, Linux only) |
| `scripts/sign-client.sh` | ntm-client (called by CMake POST_BUILD, Linux + Windows cross-compile) |

Both scripts use the same key pair. The public key is embedded at compile time in
`src/build_pubkey.hpp` (committed to the repo). The private key is never in the repo.

To generate or regenerate the key pair:
```bash
./scripts/manage-build-keys.sh
```

### Linux client + server
*(Arch Linux Agent)*

```bash
rm -f build-linux/ntm-server-linux-amd64-*
rm -f build-linux/ntm-client-linux-amd64-*
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
# build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>
# build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>.sig  (POST_BUILD signing)
# build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>
# build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>.sig  (POST_BUILD signing)
```

### Windows client (native Windows)
*(Windows Agent)*

**One-time setup** (run once, requires Administrator for PATH change):
```powershell
.\scripts\setup-toolchain-windows.ps1
```

**Every build** (from repo root in PowerShell):
```powershell
.\scripts\build-windows.ps1                   # Release
.\scripts\build-windows.ps1 -Clean            # wipe build-windows/ first
.\scripts\build-windows.ps1 -Debug            # Debug build
.\scripts\build-windows.ps1 -RunTests         # build + run unit tests
.\scripts\build-windows.ps1 -Clean -RunTests  # clean build + tests
# outputs: build-windows/ntm-client-windows-amd64-<MAJOR.MINOR.PATCH.REVISION>.exe
#          build-windows/ntm-client-windows-amd64-<MAJOR.MINOR.PATCH.REVISION>.exe.sig  (POST_BUILD signing)
#          build-windows/ntm-tests-windows.exe
```

**Run tests directly:**
```powershell
build-windows\ntm-tests-windows.exe
ctest --test-dir build-windows --output-on-failure
```

Or manually with cmake:
```powershell
cmake -B build-windows -G Ninja `
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-mingw64.cmake `
      -DNPCAP_SDK="C:/npcap-sdk" `
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows -j $env:NUMBER_OF_PROCESSORS
```

**Dependencies (Windows Agent machine):**

| Dependency | Location after setup |
|---|---|
| MSYS2 | `C:\msys64` — install via `winget install MSYS2.MSYS2` |
| MinGW-w64 GCC 16 | `C:\msys64\mingw64\bin\g++.exe` — installed by setup script |
| CMake 4.x | `C:\msys64\mingw64\bin\cmake.exe` — installed by setup script |
| Ninja | `C:\msys64\mingw64\bin\ninja.exe` — installed by setup script |
| OpenSSL 3.x static | `C:\msys64\mingw64\lib\libssl.a` — installed by setup script |
| Npcap SDK 1.13 | `C:\npcap-sdk` — downloaded and extracted by setup script |
| Native toolchain file | `cmake/toolchain-windows-mingw64.cmake` |

---

## Server Auto-Upgrade

The `scripts/push-upgrade.sh` script pushes a new signed server binary to the live
server via the `/admin/upgrade/push` endpoint.

### Critical policy — agents MUST NOT push autonomously

> **Agents MUST NEVER call `push-upgrade.sh --confirm` on their own initiative.**
> The `--confirm` flag must only be supplied when a human explicitly instructs the
> push in that conversation turn.  Dry-run (`push-upgrade.sh <binary>`, no flag)
> is permitted at any time for pre-flight validation.

### Prerequisites

| File | Location | Purpose |
|---|---|---|
| `ntmserver.info` | `~/.ntm/ntmserver.info` | `server=<host>` and `port=<port>` lines |
| Private build key | `~/.ntm/privatebuildkey.secret` | ML-DSA-65 key; mode 600; never in repo |

`ntmserver.info` is a build-machine-only file — **never commit it to the repository**.

### Push workflow

```bash
# 1. Build and sign (on main branch, clean working tree):
rm -f build-linux/ntm-server-linux-amd64-*
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
# Produces: build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>
#           build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>.sig

# 2. Dry-run (always do this first):
./scripts/push-upgrade.sh build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>

# 3. Push (ONLY when human explicitly requests it):
./scripts/push-upgrade.sh build-linux/ntm-server-linux-amd64-<MAJOR.MINOR.PATCH.REVISION> --confirm
```

### Branch safety (enforced by the script)

- Current branch must be `main`
- Working tree must be clean (no uncommitted changes)
- Local `main` must match `origin/main`

Any of these checks failing causes an immediate error — no partial push.

### Server-side behaviour on receiving a push

1. Verifies the ML-DSA-65 auth proof (nonce + binary hash, signed with build key)
2. Verifies the ML-DSA-65 binary signature (same embedded public key)
3. If new version ≤ current version → logs warning, returns 409 Conflict, discards
4. Atomically replaces the binary at its current path (same filename → systemd compatibility)
5. Returns HTTP 200 and schedules a graceful restart after 30 s connection drain

---

## Client Binary Push

The `scripts/push-client.sh` script pushes a signed ntm-client binary into the
server's `update_dir` via the `/admin/client/push` endpoint. Connected clients
then receive it automatically on their next update check.

### Critical policy — agents MUST NOT push autonomously

> **Agents MUST NEVER call `push-client.sh --confirm` on their own initiative.**
> The `--confirm` flag must only be supplied when a human explicitly instructs the
> push in that conversation turn.  Dry-run (`push-client.sh <binary>`, no flag)
> is permitted at any time for pre-flight validation.

### Prerequisites

| File | Location | Purpose |
|---|---|---|
| `ntmserver.info` | `~/.ntm/ntmserver.info` | `server=<host>` and `port=<port>` lines |
| Private build key | `~/.ntm/privatebuildkey.secret` | ML-DSA-65 key; mode 600; never in repo |

### Push workflow

```bash
# 1. Build and sign (on main branch, clean working tree):
rm -f build-linux/ntm-client-linux-amd64-*
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
# Produces: build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>
#           build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>.sig

# 2. Dry-run (always do this first):
./scripts/push-client.sh build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION>

# 3. Push (ONLY when human explicitly requests it):
./scripts/push-client.sh build-linux/ntm-client-linux-amd64-<MAJOR.MINOR.PATCH.REVISION> --confirm
```

For Windows client binaries (cross-compiled on Linux):
```bash
./scripts/push-client.sh build-linux/ntm-client-windows-amd64-<MAJOR.MINOR.PATCH.REVISION>.exe --confirm
```

### Branch safety (enforced by the script)

Same as server push: branch must be `main`, working tree clean, matches origin/main.

### Server-side behaviour on receiving a push

1. Verifies ML-DSA-65 auth proof (nonce + binary hash, signed with build key)
2. Validates filename format and platform
3. Verifies ML-DSA-65 binary signature (embedded build public key)
4. If pushed version ≤ current version for that platform → returns 409 Conflict, discards
5. Writes binary + sig atomically to `update_dir`
6. Triggers `update_dir` housekeeping (see below)

### `update_dir` housekeeping

The server automatically keeps `update_dir` clean on every scan (startup, manual
rescan, and after each successful client push). The rules are:

- **Valid pair**: binary matching `ntm-client-<platform>-<version>[.exe]` AND a
  matching `.sig` file that verifies with the embedded build public key.
- **Keep**: the highest-version valid pair per platform.
- **Delete**: everything else — orphan `.sig` files, binaries without a valid `.sig`,
  pairs where signature verification fails, older versions, and unrecognised files.

**Deployment rule**: always copy the `.sig` file before or simultaneously with the
binary. A binary without its `.sig` is deleted on the next scan.

### Binary integrity on client side

Every ntm-client binary verifies its own ML-DSA-65 signature at startup (Step 0
of `main()`). If the `.sig` file is missing or the signature fails, the client
refuses to start with a FATAL error. Both the binary and its `.sig` must be
deployed together.

The auto-updater (`updater.cpp`) also downloads the `.sig` alongside the new
binary and verifies it before applying the update. An update that fails
ML-DSA-65 verification is discarded without touching the filesystem.


