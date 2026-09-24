# network-traffic-monitor — Project Rules

Project-specific facts for the `network-traffic-monitor` repo. Read this
alongside `docs/agent-framework.md`, which defines the generic multi-agent
workflow mechanics. If the two documents ever conflict, **this file wins**.

---

## 1. Project overview

`network-traffic-monitor` (NTM) is a self-hosted network monitoring system
consisting of an `ntm-server` (C++, Linux), an `ntm-client` (C++, Linux and
Windows), two iOS companion apps (NTMDashboard and NTMClient), and a
browser-based admin dashboard embedded in the server binary. Three Claude Code
agents collaborate in parallel under a **hub-and-spoke** model
(`docs/agent-framework.md §0`): the Fedora Linux Agent is the **Architect** (the
hub) and also owns server/client C++ and shared headers; the Swift Agent owns
iOS code; the Windows Agent owns Windows-specific client code and the Windows
build. All cross-agent work is brokered by the Architect, and **only the
Architect merges PRs into `main`**.

---

## 2. Concrete agent roles

### 2.1 Environment detection

Run the appropriate command for your platform at the start of each session to
identify your role.

**On Linux:**

```bash
uname -s                        # must return "Linux"
[ -f /etc/fedora-release ] && echo "Fedora Linux" || echo "other Linux"
```

**On macOS:**

```bash
uname -s                        # returns "Darwin"
```

**On Windows (PowerShell):**

```powershell
$env:OS                         # returns "Windows_NT"
```

### 2.2 Role and ownership table

| Environment | Detection | Role | Branch prefix | **Recipient tag** | Code ownership | Merges to `main`? |
|---|---|---|---|---|---|---|
| Fedora Linux | `uname -s` = `Linux` **and** `/etc/fedora-release` exists | **Fedora Linux Agent** — also the **Architect** | `linux/` | **`[ARCHITECT]`** | `src/` server + Linux client · shared headers · CMake (Linux) · `docs/` · config files · Linux/server deployment guides · `CLAUDE.md` | **Yes** — and docs-only direct commits |
| macOS | `uname -s` = `Darwin` | **Swift Agent** | `ios/` | **`[SWIFT AGENT]`** | `ios/` · XcodeGen · Swift/iOS code | No — PR only |
| Windows | `$env:OS` = `Windows_NT` | **Windows Agent** | `win/` | **`[WINDOWS AGENT]`** | `src/` Windows-specific client code · `cmake/toolchain-windows-mingw64.cmake` (native, used by §9) · `cmake/toolchain-mingw64.cmake` (legacy Linux cross-compile) · Windows CMake config · Windows deployment guide · Npcap/WinSock integration | No — PR only |

> ### The **Recipient tag** column is the closed set that framework §4.4 points at
>
> The tag is the **role name, uppercased** — never the branch prefix. Those are
> deliberately different spellings of the same role and must never be substituted.
> `[ARCHITECT]` is the one abbreviation (never `[ARCHITECT AGENT]`).
>
> ⚠️ **A wrong tag is worse than a missing one.** `gh issue list --search 'in:title
> "[LINUX AGENT]"'` returns **0 by construction** and reads *identically* to a
> genuinely empty inbox — no error, no warning. The title tag is the only live
> routing mechanism in this repo; issue assignees are not used.

> **Merge vs. commit.** The last column is about *direct commits*. **Merging PRs**
> is separate and **Architect-only** (framework §3.5) — no agent in this table may
> merge any PR to `main`, or prompt a human to merge on its behalf.

### 2.3 Fedora Linux Agent

**Owns:** C++ server code, Linux client code, and all shared/protocol headers
in `src/`; CMake build system (Linux targets); `docs/`; config file examples;
Linux and server deployment guides; wire-protocol and API-protocol specs.

**Responsibilities:**
- Writes and maintains all C++ code for `ntm-server` and `ntm-client` (Linux).
- Maintains shared headers used by all C++ targets (e.g. `proto_client_server.hpp`).
- Writes documentation, config examples, and Linux/server deployment guides.
- Builds the Linux server and Linux client binaries (see §9 Linux build).
- **Does not** build the Windows client — the Windows Agent owns that.
- **Does not** run XcodeGen, Xcode builds, or on-device tests.
- **Does not** write Swift code — use PR handoff instead (see `docs/agent-framework.md §4`).

### 2.4 Swift Agent (macOS)

**Owns:** all Swift/iOS code (`ios/NTMDashboard/`, `ios/NTMClient/`), XcodeGen
project files (`ios/project.yml`, per-app `project.yml`), and any future macOS
native code.

**Responsibilities:**
- Writes and maintains all Swift code for iOS apps (NTMDashboard, NTMClient).
- Applies iOS-side protocol lockstep changes (e.g. bumping `supportedApiVersion`,
  adding new model fields) when a protocol version lands on `main`.
- Runs XcodeGen (`xcodegen generate`) and builds in Xcode (⌘B).
- Runs on-device and simulator tests; handles App Store / TestFlight publishing.
- **Does not** write C++ code — it files an `[ARCHITECT]` request instead
  (framework §4.0a).
- **Does not merge** its own PR, and does not ask a human to merge it
  (framework §3.5).

**One-time git hook setup (run once per clone):**

```bash
git config core.hooksPath scripts/hooks
```

Xcode has no cmake configure step, so the pre-commit hook is not installed
automatically. This single command activates it. Without it, version-bump
enforcement is silently absent for iOS commits.

### 2.5 Windows Agent

**Owns:** all Windows-specific C++ client code in `src/` (files conditionally
compiled for Windows, `#ifdef _WIN32` blocks, and any `*_windows*`-named
files); `cmake/toolchain-windows-mingw64.cmake` (native build, §9) and `cmake/toolchain-mingw64.cmake` (legacy cross-compile); Windows-specific CMake variables and
targets; `CLIENT_DEPLOYMENT.md` Windows sections; Npcap SDK and WinSock
integration.

**Responsibilities:**
- Writes and maintains all Windows-specific code for `ntm-client` (Windows).
- Builds the Windows client natively on Windows (see §9 Windows build).
- Maintains the Windows toolchain file and Windows CMake configuration.
- Writes and updates Windows deployment documentation.
- Manages Npcap SDK, WinSock2, and any other Windows-only dependencies.
- Applies Windows-side protocol lockstep changes when a protocol version lands
  on `main`.
- **Does not** build the Linux server or Linux client — the Fedora Linux Agent
  owns that.
- **Does not** write Swift code — it files an `[ARCHITECT]` request instead
  (framework §4.0a).
- **Does not merge** its own PR, and does not ask a human to merge it
  (framework §3.5).

---

### 2.6 Architect Agent (held by the Fedora Linux Agent)

The Architect is the hub of framework §0. In this project the role is **not a
separate session** — it is held by the Fedora Linux Agent, which keeps the code
ownership listed in §2.2 unchanged.

**Architect duties, in addition to its own domain:**

- **Dispatches all cross-agent work** (`[<RECIPIENT>] [<KIND>]` Issues, framework
  §4.1). No other agent may create a work order.
- **Merges every PR into `main`** (framework §3.5), closes the dispatching Issue
  with an outcome comment, and deletes the branch.
- **Rules on dissent** (framework §4.3) and escalates to the human when it cannot
  converge with the owning agent.
- **Is the only agent that talks to the maintainer** (framework §7.0, §7.2), and
  records every human authorisation on the thread with its exact scope.
- **Lands protocol changes directly on `main`** (§4, framework §6.1).
- **Owns the governance docs** — `CLAUDE.md`, `docs/agent-framework.md`,
  `docs/project-rules.md`. The documents that constrain the agents are not
  writable by the agents they constrain.
- **Runs the board sweep** (framework §12.4) and the stop condition (§12.5).

> ⚠️ **This is a working Architect, and that is a known weakening.** It also owns
> the C++ server, the Linux client and `docs/`, so the hub cannot be kept
> empty-handed. The mitigations in framework §0 are binding: dispatch to the Swift
> and Windows lanes *before* starting a long local build, announce a blocking
> execution on the board, and never start one while a dispatch is unanswered or a
> dissent is unruled.

### 2.12 Peer messaging roster (project-specific)

The doorbell transport of framework §4.0b. **GitHub remains the system of
record** — nothing here may *be* the record.

| Role | Session name | Host | Transport |
|---|---|---|---|
| Architect / Fedora Linux Agent | `NTM-Architect` | Fedora (this machine) | local |
| Swift Agent | `NTM-Swift` | macOS | Remote Control |
| Windows Agent | `NTM-Windows` | Windows (host `A8`) | Remote Control |

**Roster hygiene.** `ListAgents` shows no host and lists stale rows from ended
sessions, so a name is a *label*, not proof. Prefer replying with the incoming
message's `from=` copied verbatim. A send to a Remote Control session **reports
nothing back** — silence is not agreement, and delivery is unconfirmed until the
recipient says so.

**Session naming.** Each agent session is named `NTM-<role>` so the roster above
resolves. Set it with `/rename` at session start if it is not already.

---

## 3. Module list and version files

Each module is versioned independently using `MAJOR.MINOR.PATCH.REVISION`
(see `docs/agent-framework.md §5` for the versioning rules).

| Module | Version file | Constant |
|---|---|---|
| `ntm-server` | `src/server_version.hpp` | `kServerVersion` |
| `ntm-client` (Linux / Windows) | `src/client_version.hpp` | `kClientVersion` |
| NTMClient (iOS) | `ios/NTMClient/Shared/ClientVersion.swift` | `kClientVersion` |
| NTMDashboard (iOS) | `ios/project.yml` → `MARKETING_VERSION` | App Store version |

---

## 4. Protocol documents and constants

Two protocol documents in `docs/` are the authoritative specifications:

| Document | Covers |
|---|---|
| `docs/wire-protocol.md` | ntm-client ↔ ntm-server TCP ingestion channel |
| `docs/api-protocol.md` | ntm-server ↔ dashboard clients HTTPS API |

Both protocol version constants live in `src/proto_client_server.hpp`:

| Constant | Current value | Protocol |
|---|---|---|
| `kWireProtoVersion` | `4` | Wire (data-phase line format) |
| `kApiVersion` | `14` | HTTPS API (endpoint schemas) |

### Protocol lockstep table

When a protocol version bumps, every module in the table below must receive at
least a MINOR bump in the same commit. A breaking change requires MAJOR for all
of them. (See `docs/agent-framework.md §6` for the governance rules.)

| Protocol | Lockstep modules | Responsible agents |
|---|---|---|
| Wire (`kWireProtoVersion`) | `ntm-server`, `ntm-client` (Linux), `ntm-client` (Windows), `NTMClient` (iOS) | Fedora Linux Agent · Windows Agent · Swift Agent |
| API (`kApiVersion`) | `ntm-server`, `NTMDashboard` (iOS), embedded web dashboard | Fedora Linux Agent · Swift Agent |

---

## 5. Client Configuration Key Parity

All ntm-client configuration keys are parsed by the single shared file
`src/client_config_parse.hpp` and stored in `src/client_types.hpp::ClientConfig`.
Both Linux and Windows clients `#include` these files without any
platform-specific branches, ensuring they always accept an identical set of keys.

### Rules

1. **All configuration keys MUST be added to `src/client_config_parse.hpp`
   exclusively — never in platform-specific files** — so that Linux and Windows
   clients always accept an identical set of configuration keys.

2. **All config keys must have identical runtime behaviour on all platforms.**
   Intentional platform exceptions (e.g. a feature not yet implemented on one
   platform) require:
   - Explicit documentation in `CLIENT_DEPLOYMENT.md` (noting the limitation
     and which platforms are affected).
   - A cross-agent handoff PR to the owning agent to resolve the gap before the
     next MINOR release of ntm-client.

3. **All config fields reported in H-lines (`cfg_*` fields) must reflect the
   actual runtime value on both platforms.** If a field's behaviour differs
   between platforms, the H-line must accurately reflect the effective value
   (e.g. `cfg_compress=0` on a platform where compression is disabled) so the
   admin dashboard shows the true state.

---

## 6. Shared Client Sources — Cross-Platform Rebuild Rule

The following files are compiled into **both** the Linux and Windows
`ntm-client` binaries (the `NTM_CLIENT_COMMON_SOURCES` list in
`CMakeLists.txt`, plus the shared version header):

```
src/client_main.cpp
src/client_core.cpp
src/client_impl.cpp
src/client_transport_tcptls.cpp
src/client_transport_websocket.cpp
src/updater.cpp
src/client_version.hpp          (version constant and platform identifier)
src/client_config_parse.hpp     (config parsing — see §5)
src/client_types.hpp            (ClientConfig struct)
```

### Rule

**Any commit that modifies a shared client source file listed above MUST be
followed by a cross-agent handoff PR to the other client agent(s) to rebuild
and push their binary.** Specifically:

- **Fedora Linux Agent (Architect)** modifies a shared file → it **dispatches**
  a `[WINDOWS AGENT] [CODE]` Issue asking the Windows Agent to rebuild
  `ntm-client-windows-amd64-<version>.exe`. The push itself is human-gated (§10,
  §11) and is authorised through the Architect (framework §7.0).

- **Windows Agent** modifies a shared file → it files an **`[ARCHITECT]`
  request** (framework §4.0a) stating that the Linux client needs a matching
  rebuild. It does **not** open a work order for another agent, and it does not
  open a handoff PR — that branch class is retired.

**Why this matters:** Clients on both platforms auto-update from the same
`update_dir`. If only one platform ships a bug fix or feature, the other
platform's users are left on broken or outdated code indefinitely. Both
binaries must ship together.

The dispatch (or request) must include:
- The specific version to build (`ntm-client X.Y.Z.R`)
- A one-line summary of what changed and why
- Whether a push is being asked for — and if so, that it awaits a recorded human
  authorisation (framework §7.0), never the agent's own initiative

---

## 7. Apple Distribution cert reference (iOS)

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

If the line is missing, the private key is not in keychain. Import from a
`.p12` export of the original signing Mac — do **not** commit the `.p12`.

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

## 8. Demo Server

Port 12345 serves mock `/api/summary` data for App Store review (no auth,
iOS only).

**Consistency rule**: Any change to the `/api/summary` JSON schema (new field,
renamed field, removed field, changed type) **must** be reflected in
`buildDemoSummaryJson()` in `src/web_dashboard.cpp` in the same commit. The
mock data must mirror the real schema exactly.

---

## 9. C++ Build

Each agent builds only its own platform binaries. The output filenames embed
the platform and version (e.g. `ntm-client-linux-amd64-1.14.1.0`) and match
the auto-update naming convention exactly — they can be dropped directly into
`update_dir` on the server without renaming.

### Stale binary cleanup (required on every version bump)

Because the version is baked into the filename, a version bump produces a
**new filename** while the old binary stays in the build directory. **Always
delete old versioned binaries before or after building a new version** to avoid
deploying the wrong file by mistake.

```bash
# Linux — remove old client binaries before building the new one
rm -f build-linux/ntm-client-linux-amd64-*

# Linux — remove old server binaries before building the new one
rm -f build-linux/ntm-server-linux-amd64-*
```

```powershell
# Windows — remove old client binaries before building the new one
Remove-Item build-windows\ntm-client-windows-amd64-*.exe -ErrorAction SilentlyContinue
```

### Binary signing (all platforms)

Every ntm-server and ntm-client binary is **ML-DSA-65 signed at build time** as
a mandatory POST_BUILD step. An unsigned binary is never produced — if the
private key (`~/.ntm/privatebuildkey.secret`) is absent the build fails
immediately.

| Script | Signs |
|---|---|
| `scripts/sign-server.sh` | ntm-server (called by CMake POST_BUILD, Linux only) |
| `scripts/sign-client.sh` | ntm-client (called by CMake POST_BUILD, Linux + Windows cross-compile) |

Both scripts use the same key pair. The public key is embedded at compile time
in `src/build_pubkey.hpp` (committed to the repo). The private key is never in
the repo.

To generate or regenerate the key pair:

```bash
./scripts/manage-build-keys.sh
```

### Linux client + server *(Fedora Linux Agent)*

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

### Windows client — native Windows *(Windows Agent)*

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
#          build-windows/ntm-client-windows-amd64-<MAJOR.MINOR.PATCH.REVISION>.exe.sig
#          build-windows/ntm-tests-windows.exe
```

**Run tests directly:**

```powershell
build-windows\ntm-tests-windows.exe
ctest --test-dir build-windows --output-on-failure
```

**Or manually with cmake:**

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
| MSYS2 `diffutils` (`cmp`) | `C:\msys64\usr\bin\cmp.exe` — `pacman -S --needed diffutils`; required by key/signing verification steps (not in the MSYS2 base install; found in #135) |
| MSYS2 `gdb` | `C:\msys64\mingw64\bin\gdb.exe` — `mingw-w64-x86_64-gdb`; debugging |
| Native toolchain file | `cmake/toolchain-windows-mingw64.cmake` |

> **PowerShell 5.1 procedures must be ASCII-only** (no em dashes or curly quotes). Without a UTF-8 BOM, PS 5.1 reads a `.ps1` as ANSI, and a mis-decoded `—` yields a byte PowerShell parses as a quote, so the whole script fails to parse (#135). Native calls do not throw on failure. Check `$LASTEXITCODE` explicitly.

---

## 10. Server Auto-Upgrade

The `scripts/push-upgrade.sh` script pushes a new signed server binary to the
live server via the `/admin/upgrade/push` endpoint.

### Critical policy

> **Agents MUST NEVER call `push-upgrade.sh --confirm` on their own
> initiative.** The `--confirm` flag must only be supplied when a human
> explicitly instructs the push in that conversation turn. Dry-run
> (`push-upgrade.sh <binary>`, no flag) is permitted at any time for
> pre-flight validation.
>
> See `docs/agent-framework.md §7` for the general production-push policy.

### Prerequisites

| File | Location | Purpose |
|---|---|---|
| `ntmserver.info` | `~/.ntm/ntmserver.info` | `server=<host>` and `port=<port>` lines |
| Private build key | `~/.ntm/privatebuildkey.secret` | ML-DSA-65 key; mode 600; never in repo |

`ntmserver.info` is a build-machine-only file — **never commit it to the
repository**.

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

## 11. Client Binary Push

The `scripts/push-client.sh` script pushes a signed ntm-client binary into the
server's `update_dir` via the `/admin/client/push` endpoint. Connected clients
then receive it automatically on their next update check.

### Critical policy

> **Agents MUST NEVER call `push-client.sh --confirm` on their own
> initiative.** The `--confirm` flag must only be supplied when a human
> explicitly instructs the push in that conversation turn. Dry-run
> (`push-client.sh <binary>`, no flag) is permitted at any time for
> pre-flight validation.
>
> See `docs/agent-framework.md §7` for the general production-push policy.

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

For Windows client binaries:

```bash
./scripts/push-client.sh build-linux/ntm-client-windows-amd64-<MAJOR.MINOR.PATCH.REVISION>.exe --confirm
```

### Branch safety (enforced by the script)

Same as server push: branch must be `main`, working tree clean, matches
`origin/main`.

### Server-side behaviour on receiving a push

1. Verifies ML-DSA-65 auth proof (nonce + binary hash, signed with build key)
2. Validates filename format and platform
3. Verifies ML-DSA-65 binary signature (embedded build public key)
4. If pushed version ≤ current version for that platform → returns 409 Conflict, discards
5. Writes binary + sig atomically to `update_dir`
6. Triggers `update_dir` housekeeping (see below)

### `update_dir` housekeeping

The server automatically keeps `update_dir` clean on every scan (startup,
manual rescan, and after each successful client push). The rules are:

- **Valid pair**: binary matching `ntm-client-<platform>-<version>[.exe]` AND
  a matching `.sig` file that verifies with the embedded build public key.
- **Keep**: the highest-version valid pair per platform.
- **Delete**: everything else — orphan `.sig` files, binaries without a valid
  `.sig`, pairs where signature verification fails, older versions, and
  unrecognised files.

**Deployment rule**: always copy the `.sig` file before or simultaneously with
the binary. A binary without its `.sig` is deleted on the next scan.

### Binary integrity on client side

Every ntm-client binary verifies its own ML-DSA-65 signature at startup (Step
0 of `main()`). If the `.sig` file is missing or the signature fails, the
client refuses to start with a FATAL error. Both the binary and its `.sig` must
be deployed together.

The auto-updater (`updater.cpp`) also downloads the `.sig` alongside the new
binary and verifies it before applying the update. An update that fails
ML-DSA-65 verification is discarded without touching the filesystem.
