# network-traffic-monitor

## Agent Roles

Two Claude Code agents collaborate on this project. Each agent **detects its
own role from the OS at the start of every session** — no manual configuration needed.

Run `uname -s` and `uname -r` to identify the environment:

| Environment | Detection | Role | Platform ownership |
|---|---|---|---|
| Linux / WSL2 | `uname -s` = `Linux` and `uname -r` contains `microsoft` | **C++ Agent** | Linux server · Linux client · Windows client |
| macOS | `uname -s` = `Darwin` | **Swift Agent** | iOS apps · future macOS apps |

---

### C++ Agent (Linux / WSL2)

**Owns:** all C++ code (`src/`), CMake build system, documentation, config files,
deployment guides, wire-protocol and API-protocol specs.

**Responsibilities:**
- Writes and maintains all C++ code: `ntm-server`, `ntm-client` (Linux + Windows).
- Writes documentation, config examples, and deployment guides.
- Builds Linux server + client **and** cross-compiles Windows client on every build
  (see [C++ Build](#c-build) below).
- Commits and pushes to **feature branches** (never directly to `main`).
- Opens PRs targeting `main` when a unit of work is ready for the Swift Agent.
- Reads Swift Agent PR comments and iterates until all checklist items pass.
- Signals the Swift Agent to merge by commenting `ready to merge` on the PR.
- **Does not** run XcodeGen, Xcode builds, or on-device tests.
- **Does not** write Swift code — if a Swift change is needed, describe it clearly
  in a PR comment so the Swift Agent can implement it.

---

### Swift Agent (macOS)

**Owns:** all Swift/iOS code (`ios/NTMDashboard/`, `ios/NTMClient/`), XcodeGen
project files (`ios/project.yml`, per-app `project.yml`), and any future macOS
native code.

**Responsibilities:**
- Writes and maintains all Swift code for iOS apps (NTMDashboard, NTMClient).
- Applies iOS-side protocol lockstep changes (e.g. bumping `supportedApiVersion`,
  adding new model fields) when the C++ Agent bumps a protocol version.
- Runs XcodeGen (`xcodegen generate`) and builds in Xcode (⌘B).
- Runs on-device and simulator tests; handles App Store / TestFlight publishing.
- Reports build and test results as a PR comment covering every checklist item.
- Merges the PR only after the C++ Agent comments `ready to merge`.
- After merging, **deletes the feature branch** — both local and remote:
  ```
  git branch -d <branch>
  git push origin --delete <branch>
  ```
- **Does not** write C++ code — if a C++ change is needed, describe it in a PR
  comment with the tag `[ACTION REQUIRED — C++ AGENT]` so the C++ Agent picks
  it up on its next session.

---

### Handoff: C++ Agent → Swift Agent

The C++ Agent opens every PR with this structure:

```
## Build instructions
<xcodegen / cmake commands>

## Test checklist
- [ ] item 1
- [ ] item 2

## Watch for
<known risks or areas that need close attention>

## Files changed (focus areas)
<brief list of the most relevant changed files>
```

The Swift Agent replies with a PR comment covering each checklist item and any
unexpected findings.

---

### Handoff: Swift Agent → C++ Agent

When the Swift Agent needs C++ changes (bug found, new API endpoint needed, protocol
mismatch, etc.) it leaves a PR comment with this structure:

```
## [ACTION REQUIRED — C++ AGENT]

### Problem
<what is wrong or missing in the C++ code>

### Required change
<specific files, functions, or behaviour that needs to change>

### Context
<why this is needed; any relevant error messages or test failures>
```

The C++ Agent reads open PR comments at the start of each session, implements the
requested changes, pushes to the same feature branch, and replies confirming what
was done. If the Swift Agent has no open PR to comment on, it opens a new issue on
GitHub describing the required C++ work.

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

| Protocol | Lockstep modules |
|---|---|
| Wire (`kWireProtoVersion`) | `ntm-server`, `ntm-client` (C++), `NTMClient` (iOS) |
| API (`kApiVersion`) | `ntm-server`, `NTMDashboard` (iOS), embedded web dashboard |

### Rules

1. **Update the relevant protocol doc before the commit that changes either side.**
   Never change a message format, field, or endpoint without updating the doc first.
2. **Bump the protocol version constant** (`kWireProtoVersion` or `kApiVersion`) when
   the change classification in the doc requires it.
3. **Both protocols are independent.** A wire-protocol change does not require an
   API version bump, and vice versa — unless the same commit touches both sides.
4. **When a protocol bumps, bump every lockstep module** per the table above.

---

## Demo Server

Port 12345 serves mock `/api/summary` data for App Store review (no auth, iOS only).

**Consistency rule**: Any change to the `/api/summary` JSON schema (new field, renamed field,
removed field, changed type) **must** be reflected in `buildDemoSummaryJson()` in
`src/web_dashboard.cpp` in the same commit. The mock data must mirror the real schema exactly.

---

## C++ Build

The Linux agent is responsible for building **both** the Linux and Windows client binaries.
Always run both builds together — the Windows binary is needed for auto-update distribution
and for operators on Windows machines.

### Linux client + server

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
# build/ntm-server
# build/ntm-client-linux-amd64-<version>
```

### Windows client (cross-compile from Linux)

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

**Dependencies (pre-installed on this machine):**

| Dependency | Location |
|---|---|
| MinGW-w64 cross-compiler | `x86_64-w64-mingw32-g++` (Arch `mingw-w64-gcc`) |
| Npcap SDK | `/opt/npcap-sdk` |
| MinGW OpenSSL static libs | `/usr/x86_64-w64-mingw32/lib64/libssl.a` + `libcrypto.a` |
| Toolchain file | `cmake/toolchain-mingw64.cmake` |

The output filenames embed the platform and version (e.g. `ntm-client-linux-amd64-1.9.0`)
and match the auto-update naming convention exactly — they can be dropped directly into
`update_dir` on the server without renaming.
