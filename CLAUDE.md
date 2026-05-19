# network-traffic-monitor

## Versioning

**Single source of truth:** `src/version.hpp` — defines `kNtmVersion`.  
Both `ntm-client` and `ntm-server` include this header; the client sends it
in every `H` (health) line as `ver=X.Y.Z`; the server displays it in the
dashboard and highlights any client whose version differs from the server's.

### Format: `MAJOR.MINOR.PATCH`

| Change type | Which part to bump | Example trigger |
|---|---|---|
| Breaking wire-protocol or auth change | MAJOR | new auth handshake, incompatible line format |
| New feature, backward-compatible | MINOR | new optional H field, new dashboard section |
| Bug fix, no protocol or feature change | PATCH | crash fix, race condition, display glitch |

### Rules

1. **Update `src/version.hpp` before the commit that introduces the change.**
   Never bump the version in a separate follow-up commit.
2. **Never skip levels.** Go 1.0.0 → 1.0.1 → 1.1.0, not 1.0.0 → 1.2.0.
3. **PATCH resets on MINOR bump; MINOR resets on MAJOR bump.**
   1.2.3 + minor feature → 1.3.0 (not 1.2.4 or 1.3.3).
4. **Bug-fix-only commits** (like race fixes or display glitches) are PATCH bumps.
5. Current version is in `src/version.hpp`. Always read it before deciding the
   next version number — do not rely on memory or git log alone.

## Protocol Governance

Two protocol documents in `docs/` are the authoritative specifications:

| Document | Covers |
|---|---|
| `docs/wire-protocol.md` | ntm-client ↔ ntm-server TCP ingestion channel |
| `docs/api-protocol.md` | ntm-server ↔ dashboard clients HTTPS API |

### Rules

1. **Update the relevant protocol doc before the commit that changes either side.**
   Never change a message format, field, or endpoint without updating the doc first.
2. **Bump the protocol version** (`kWireProtoVersion` or `api_version`) when the
   change classification in the doc requires it.
3. **Both protocols are independent.** A wire-protocol change does not require an
   API version bump, and vice versa — unless the same commit touches both sides.
4. **The ntm software version bump** (§ Versioning above) still applies on top of
   any protocol doc update.

## Phase 4 — iOS Swift (Mac/Xcode required)

> **IMPORTANT — delete this entire section from CLAUDE.md once Phase 4 is
> committed.** It is here solely to carry context to a macOS session that does
> not have access to the Linux auto-memory files.

### Background

The server-side WebAuthn RP is fully implemented (v1.3.0, commit a764758).
The iOS app scaffold (30 Swift files) exists at `ios/NTMDashboard/` but has
no passkey auth yet. Phase 4 wires the iOS app to the server's auth endpoints.

The auth API is documented in full in `docs/api-protocol.md` (§ 7).
Key flows:
- Registration: `GET /auth/register/begin` → navigator passkey create → `POST /auth/register/complete`
- Login: `GET /auth/login/begin` → navigator passkey get → `POST /auth/login/complete`
- Session: server returns `{"token":"..."}` in the login response; iOS stores it
  in the Keychain and sends it as `Authorization: Bearer <token>` on every request.
- Logout: `POST /auth/logout`

### Files to create / modify

All paths are relative to `ios/NTMDashboard/NTMDashboard/`.

| File | Action | Notes |
|---|---|---|
| `Services/KeychainService.swift` | **Create** | Store/retrieve/delete session Bearer token keyed on server URL. Use `kSecClassGenericPassword`. |
| `Services/PasskeyService.swift` | **Create** | Wrap `ASAuthorizationController` for both registration and login. Uses `ASAuthorizationPlatformPublicKeyCredentialProvider`. |
| `ViewModels/AuthViewModel.swift` | **Create** | Drives login + registration flows; calls `PasskeyService` and `KeychainService`; publishes `isAuthenticated: Bool`. |
| `Views/LoginView.swift` | **Create** | Sign-in button + "Register device" section (mirrors the web `/login` page UX). |
| `Views/RegisterDeviceView.swift` | **Create** | Admin-password field + device label + register button; computes PBKDF2+HMAC proof using CryptoKit. |
| `Services/ServerConfig.swift` | **Fix bug** | `port` defaults to `5556` (ingestion port). Change default to `8443` (web dashboard port). |

### PBKDF2 admin proof in Swift (CryptoKit)

The registration flow requires a PBKDF2-HMAC-SHA256 proof (never sending the
password). In Swift/CryptoKit:

```swift
import CryptoKit

// key = PBKDF2-HMAC-SHA256(adminPassword, pbkdf2_salt, pbkdf2_iterations)
// CryptoKit does not expose PBKDF2 directly; use CommonCrypto:
import CommonCrypto

func pbkdf2(_ password: String, salt: Data, iterations: Int) -> Data {
    var derivedKey = Data(count: 32)
    derivedKey.withUnsafeMutableBytes { derivedBytes in
        password.withCString { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes, strlen(passwordBytes),
                    saltBytes.baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    derivedBytes.baseAddress, 32)
            }
        }
    }
    return derivedKey
}

// proof = HMAC-SHA256(key, adminNonce), hex-encoded
let key = SymmetricKey(data: pbkdf2(adminPassword, salt: pbkdf2Salt, iterations: pbkdf2Iterations))
let mac = HMAC<SHA256>.authenticationCode(for: adminNonce, using: key)
let proofHex = Data(mac).map { String(format: "%02x", $0) }.joined()
```

### AASA (Apple App Site Association)

For passkeys to work on iOS, the server must serve the AASA file and
`webauthn_ios_app_id` must be set in the server config.

Format: `<TeamID>.<BundleID>`, e.g. `TEAMID1234.com.ntm.NTMDashboard`.

Find your Team ID in Xcode → Signing & Capabilities or at developer.apple.com.
The bundle ID is in `ios/project.yml` (`com.ntm.NTMDashboard`).

Add to `/etc/ntm-server/ntm-server.conf` on the server:
```ini
webauthn_ios_app_id = YOURTEAMID.com.ntm.NTMDashboard
```

### Version bump

Phase 4 adds new features to the iOS client only; no wire-protocol or API
changes. Bump `src/version.hpp`: `1.3.0` → `1.4.0` (MINOR bump, new feature).
