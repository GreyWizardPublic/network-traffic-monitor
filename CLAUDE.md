# network-traffic-monitor

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
