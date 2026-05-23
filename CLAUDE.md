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

4. **Merge the PR independently** — no sign-off from other agents is required
   unless the change touches a shared protocol (see Protocol Governance).

5. **Delete the feature branch** after merge, both local and remote:
   ```
   git branch -d <branch>
   git push origin --delete <branch>
   ```

6. **At the start of each session**, check for open PRs and GitHub Issues
   addressed to your agent (see Cross-agent handoff below) and address them
   before starting new work.

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

1. Requesting agent creates a feature branch `<my-prefix>/handoff/<desc>`, adds
   any starter code or stubs, and opens a PR targeting `main`.
2. Receiving agent picks up the PR, implements or completes the work on its own
   branch (`<my-prefix>/<desc>`), resolves the handoff PR (close or supersede),
   and merges its own PR to `main`.
3. Requesting agent rebases its active branch on the updated `main`.

The receiving agent addresses the handoff in its next session and closes the
original PR with a comment summarising what was done.

---

## Versioning

Each module is versioned **independently**. A change in one module does not
require a version bump in another unless a shared protocol also changes (see
Protocol Governance below).

### Module version files

| Module | Version file | Constant |
|---|---|---|
| `ntm-server` | `src/version.hpp` | `kServerVersion` |
| `ntm-client` (Linux / Windows) | `src/client_version.hpp` | `kClientVersion` |
| NTMClient (iOS) | `ios/NTMClient/Shared/ClientVersion.swift` | `kClientVersion` |
| NTMDashboard (iOS) | `ios/project.yml` → `MARKETING_VERSION` | App Store version |

### Format: `MAJOR.MINOR.PATCH`

| Change type | Which part to bump | Example trigger |
|---|---|---|
| Breaking wire-protocol or auth change | MAJOR | new auth handshake, incompatible line format |
| New feature, backward-compatible | MINOR | new optional H field, new dashboard section |
| Bug fix, no protocol or feature change | PATCH | crash fix, race condition, display glitch |

### Rules

1. **Update the module's version file before the commit that introduces the change.**
   Never bump the version in a separate follow-up commit.
2. **Never skip levels.** Go 1.0.0 → 1.0.1 → 1.1.0, not 1.0.0 → 1.2.0.
3. **PATCH resets on MINOR bump; MINOR resets on MAJOR bump.**
   1.2.3 + minor feature → 1.3.0 (not 1.2.4 or 1.3.3).
4. **Bug-fix-only commits** are PATCH bumps; no-feature changes never use MINOR.
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
| `kWireProtoVersion` | `1` | Wire (data-phase line format) |
| `kApiVersion` | `4` | HTTPS API (endpoint schemas) |

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

## Demo Server

Port 12345 serves mock `/api/summary` data for App Store review (no auth, iOS only).

**Consistency rule**: Any change to the `/api/summary` JSON schema (new field, renamed field,
removed field, changed type) **must** be reflected in `buildDemoSummaryJson()` in
`src/web_dashboard.cpp` in the same commit. The mock data must mirror the real schema exactly.

---

## C++ Build

Each agent builds only its own platform binaries. The output filenames embed the
platform and version (e.g. `ntm-client-linux-amd64-1.9.0`) and match the
auto-update naming convention exactly — they can be dropped directly into
`update_dir` on the server without renaming.

### Linux client + server
*(Arch Linux Agent)*

```bash
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
# build-linux/ntm-server
# build-linux/ntm-client-linux-amd64-<version>
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
# outputs: build-windows/ntm-client-windows-amd64-<version>.exe
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

**Cross-compile fallback (Arch Linux Agent only, when Windows Agent is unavailable):**
```bash
cmake -B build-windows \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
  -DNPCAP_SDK=/opt/npcap-sdk \
  -DOPENSSL_CRYPTO_LIBRARY=/usr/x86_64-w64-mingw32/lib64/libcrypto.a \
  -DOPENSSL_SSL_LIBRARY=/usr/x86_64-w64-mingw32/lib64/libssl.a \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows -j$(nproc)
# build-windows/ntm-client-windows-amd64-<version>.exe
```

| Cross-compile dependency | Location |
|---|---|
| MinGW-w64 cross-compiler | `x86_64-w64-mingw32-g++` (Arch `mingw-w64-gcc`) |
| Npcap SDK | `/opt/npcap-sdk` |
| MinGW OpenSSL static libs | `/usr/x86_64-w64-mingw32/lib64/libssl.a` + `libcrypto.a` |
| Toolchain file | `cmake/toolchain-mingw64.cmake` |
