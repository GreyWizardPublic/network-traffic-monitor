# NTM Dashboard API Protocol — Specification v14

**API version:** 14  
**Software version where introduced:** ntm-server 2.0.0  
**File owner:** This document is the authoritative specification for the HTTPS
API between `ntm-server` and any dashboard client (iOS app, web browser, or
third-party tool). Update it **before** changing any endpoint, field, or
HTTP-level behaviour. The same single-commit rule applies as for `src/version.hpp`.

---

## 1. Overview

`ntm-server` exposes a small HTTPS API for querying aggregated traffic
statistics and performing administrative actions. This API is consumed by:
- The embedded web dashboard (browser)
- The NTM Dashboard iOS app
- Any future monitoring or automation client

This API is **independent** of the client data-ingestion wire protocol (see
`docs/wire-protocol.md`). The two can be versioned and extended separately.

---

## 2. Transport & Security

| Property | Value |
|---|---|
| Protocol | HTTPS only; TLS 1.2 minimum |
| Default port | 8443 (configurable via `web_port`) |
| Network scope | **WebAuthn mode**: no source-IP restriction (authenticated by passkey session). **Legacy mode**: LAN IPs only; non-RFC-1918 / non-loopback addresses → `403`. |
| Certificate | Same cert/key as the client ingestion port. |

---

## 3. Authentication

Three authentication mechanisms exist:

### 3a. Passkey session (dashboard login)

Enabled when `webauthn_rp_id` is set in the server config. All endpoints
(except those in §7) require a valid session.

**Browser:** session established via the `/login` page; server sets an
`HttpOnly; Secure; SameSite=Strict` cookie `ntm_session=<token>`.

**iOS app:** session token returned as JSON from `/auth/login/complete` or
`/auth/apple/native`; sent in subsequent requests as `Authorization: Bearer <token>`.

Unauthenticated browser GET requests → `302` redirect to `/login`.  
Unauthenticated API requests → `401`.

Passkey sessions carry a **role**:
- `user` — can access the dashboard (`/`, `/api/summary`, `/api/client/history`, etc.) but not the admin panel.
- `admin` — full access including `/admin` and all `/api/admin/*` endpoints.

Role is determined at login time:
- **Passkey login** → always `user` role.
- **Sign in with Apple** → `admin` if the Apple ID matches a configured admin identity; otherwise `user` (or `401` if non-admin Apple sign-ins are disabled by operator).

### 3b. Sign in with Apple (admin identity)

When `siwa_service_id` is configured, operators use Sign in with Apple to gain
admin access. The server identifies admins by their Apple ID (`sub` claim in the
`id_token`). Operator configures admin email address(es) in `siwa_admins`; the
server pins the stable `sub` on first sign-in (email-bootstrap).

**Web flow:** `GET /auth/apple/start` → Apple redirects to `POST /auth/apple/callback` → server sets `ntm_session` cookie with `role=admin`.

**iOS native flow:** app posts `identityToken` to `POST /auth/apple/native` → server returns bearer token with `role` field.

### 3c. Legacy LAN-only mode

If `webauthn_rp_id` is **not** set, the server restricts access to RFC 1918
LAN IPs and loopback. No session or token is required — any LAN client can
read the API. Enable WebAuthn for production deployments exposed beyond a
trusted LAN.

---

## 4. Rate Limiting

| Endpoint group | Limit |
|---|---|
| All auth-exempt endpoints | 30 requests / IP / minute |
| `POST /api/admin/purge` | 5 requests / IP / minute |
| `POST /api/admin/client/register` | 5 requests / IP / minute |
| `POST /api/admin/register/complete` | 5 requests / IP / minute |

Exceeded → `429` with `Retry-After: 60`.

---

## 5. API Versioning

Every response from `/api/summary` includes:

```json
"api_version": 14
```

This integer identifies the API contract revision, independent of the ntm
software version (`server_version`).

### Client behaviour by `api_version`

| Observed value | Client action |
|---|---|
| Equal to the highest version the client knows | Normal operation |
| Higher than the highest version the client knows | Show "server is newer; update the app" notice; continue if changes appear additive |
| Lower than the minimum the client requires | Show "server is too old" and disable the data fetch |

### Change classification

| Change | Required action |
|---|---|
| Add an optional field to any response | No bump — clients must ignore unknown JSON fields |
| Remove or rename a field | Bump `api_version`; deprecate old field one version before removal |
| Add a new endpoint | Bump `api_version`; old clients simply never call it |
| Change a field's type or semantics | Breaking change; bump `api_version`; support old version in parallel for one release cycle |

### Change log

| Version | Change |
|---|---|
| 14 | **Breaking — admin auth overhaul.** Removed admin-password authentication: `POST /api/admin/auth`, `GET /auth/register/begin`, `POST /auth/register/complete` (password-gated), and the short-lived `ntm_admin` proof-cookie system are gone. Admin sessions are now established via Sign in with Apple (`GET /auth/apple/start`, `POST /auth/apple/callback`, `POST /auth/apple/native`) and are role-tagged on the `ntm_session` token itself. Added `GET /api/session` (role/identity query). Added passkey management: `GET /api/admin/passkeys`, `DELETE /api/admin/passkeys/:credId`, `GET /api/admin/register/begin`, `POST /api/admin/register/complete` (admin-session-gated, no password). NTMDashboard must implement native SIWA (`ASAuthorizationAppleIDProvider`) to retain admin access (ntm-server 2.0.0). |
| 13 | Added remote update push endpoints: `POST /api/admin/clients/<id>/update`, `GET /api/admin/clients/<id>/update/status`. The `force` field is removed from `/api/update/check` (ntm-server 1.26.0). |
| 12 | Added remote log management endpoints: `GET /admin/clients/<id>/logs`, `POST /admin/clients/<id>/loglevel`, `GET /admin/clients/<id>/logs/<filename>`, `DELETE /admin/clients/<id>/logs/<filename>`, `DELETE /admin/clients/<id>/logs`. Commands are delivered to the client via the wire-protocol v3 `C`-line channel; responses arrive as `L` lines. Requires wire-protocol v3 clients (ntm-server 1.25.0, ntm-client 1.20.0). |
| 11 | Added admin client config endpoint: `GET /api/admin/client/config`. Clients report `cfg_*` fields in H-lines; server returns them to the admin dashboard (ntm-server 1.23.0, ntm-client 1.17.0). |
| 10 | Added admin hide-entities feature: `GET /api/admin/clients`, `GET /api/admin/hidden`, `POST /api/admin/hidden/client`, `POST /api/admin/hidden/interface`. Hidden clients and (client, iface) pairs are suppressed from `/api/summary` responses (all sections). Persisted across server restarts in `hidden_entities_file`. Enabled when `hidden_entities_file` and WebAuthn are configured (ntm-server 1.22.0). |
| 9 | Added `GET /api/client/history` — per-client traffic histogram data (in/out bytes and packets per minute or per hour). Returns a fine ring (last N 1-minute buckets) or a coarse ring (hourly aggregation across the full retention window). Requires authenticated session; rate-limited to 30 req/IP/min (ntm-server 1.21.0). |
| 8 | Added `GET /api/update/download_sig` — download ML-DSA-65 signature file for the client binary. Added `sig_size` field to `/api/update/check` response. Added client push endpoints `GET /admin/client/nonce` and `POST /admin/client/push` — push signed client binaries into `update_dir` via ML-DSA-65 authenticated upload (ntm-server 1.19.0, ntm-client 1.15.0). |
| 7 | Added auto-update endpoints: `GET /api/update/check`, `GET /api/update/download`, `POST /api/admin/update/scan`, `POST /api/admin/update/force`. Added `client_id` and `platform` fields to each `client_health` entry. Added `update_manifest` array to `/api/summary`. Added admin session endpoints `GET /api/admin/monitors` (ntm-server 1.12.0). |
| 6 | Added Internet/Local traffic split: `entities_internet`, `truncated_internet`, `entities_local`, `truncated_local`, `local_summary` to `/api/summary`. Added `GET /api/admin/monitors`, `POST /api/admin/demo`. Admin session token support (30 min TTL) for legacy password mode. NTMDashboard 1.3.0, ntm-server 1.11.0. |
| 5 | Added `POST /api/demo/begin` — unauthenticated demo session endpoint on the main web server port. Returns a short-lived `demo_…` bearer token when demo mode is enabled by the operator. `/api/summary` returns `buildDemoSummaryJson()` mock data for demo tokens. Replaces the separate port-12345 demo server for iOS clients (ntm-server 1.10.0, NTMDashboard 1.2.0). |
| 4 | `entities` now contains only non-overhead (regular) flows. Added `overhead_entities`, `truncated_overhead`, and `overhead_summary` to `/api/summary`. Overhead = flows involving ntm-clients, the server itself, or dashboard viewers (ntm 1.8.0). Added optional `server_wire_proto_version` root field; optional `wire_proto_version` + `wire_proto_ok` per client-health entry; `proto_rejected_clients` array. These are additive optional fields and do not require a version bump (ntm-server 1.8.1). |
| 3 | Added `POST /api/admin/client/register` — enrol Ed25519 wire-protocol client keys at runtime via the HTTPS API (ntm 1.5.0). |
| 2 | Added WebAuthn passkey authentication; auth endpoints `/auth/*`; `/login` page; AASA endpoint. Bumped `api_version` field to `2` (ntm 1.3.0). |
| 1 | Initial version (ntm 1.2.0) |

---

## 6. Common Response Conventions

### Success

HTTP `200` with `Content-Type: application/json`.

### Error envelope

All non-`200` responses return JSON regardless of endpoint:

```json
{ "error": "<human-readable reason>" }
```

### HTTP status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `302` | Redirect to `/login` (unauthenticated browser request, WebAuthn mode) or redirect to `/admin`/`/` after successful Apple sign-in |
| `400` | Malformed request body (missing required fields) |
| `401` | Authentication required or failed |
| `403` | Admin session required; or request source IP is not in LAN range (legacy mode only) |
| `404` | Resource not found |
| `429` | Rate limit exceeded |

### Security headers (on every response)

```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

---

## 7. Authentication Endpoints

These endpoints are always accessible without a session (they establish one).

### `GET /auth/apple/start` *(api_version 14+, SIWA mode)*

Initiates the Sign in with Apple web flow. Generates a random `state` and `nonce`,
stores them server-side (10-minute TTL), and redirects the browser to Apple's
authorization endpoint.

**Response:** `302` redirect to `https://appleid.apple.com/auth/authorize?...`

Apple will POST the result to `/auth/apple/callback`.

### `POST /auth/apple/callback` *(api_version 14+, SIWA mode)*

Apple's form-post callback. The `state` in the request body is matched against the
server-side pending entry; the `id_token` JWT is validated (RS256 against Apple JWKS,
`iss`, `aud`, `exp`, `nonce` claims). On success, the Apple `sub` is matched against
the configured admin identities.

**Request:** `application/x-www-form-urlencoded` (from Apple)

| Field | Description |
|---|---|
| `state` | Opaque value from `/auth/apple/start` |
| `id_token` | RS256-signed JWT from Apple |
| `code` | One-time auth code (not used by server — `id_token` is validated directly) |

**On success:** sets `ntm_session` cookie and redirects to `/admin` (admin role) or `/` (user role).

**On failure:** `401` with plain-text error.

### `POST /auth/apple/native` *(api_version 14+, SIWA mode)*

iOS native Sign in with Apple flow. The app posts the `identityToken` from
`ASAuthorizationAppleIDCredential` directly; the server validates it and returns
a bearer token with a `role` field.

**Request body** (`Content-Type: application/json`):

```json
{ "identity_token": "<base64url id_token JWT>" }
```

**Success response** (`200`):

```json
{ "ok": true, "token": "<Bearer token>", "role": "admin" | "user" }
```

The `token` is stored and sent as `Authorization: Bearer <token>` on subsequent
requests, identical to the passkey flow token from `/auth/login/complete`.

**Error response:** `401` with `{"error": "<reason>"}`.

### `GET /auth/login/begin`

Starts passkey authentication. Returns a challenge and the list of registered
credential IDs to pass to `navigator.credentials.get()`.

**Response** (`200`):

```json
{
  "session_key":    "<opaque pending-session token>",
  "challenge":      "<base64url, 32 random bytes>",
  "rp_id":          "<RP ID>",
  "credential_ids": ["<base64url>", ...]
}
```

### `POST /auth/login/complete`

Verifies the WebAuthn assertion. On success, sets a session cookie for the
browser and returns the Bearer token for the iOS app. Passkey sessions always
have `role: "user"`.

**Request body** (`Content-Type: application/json`):

```json
{
  "session_key":        "<from beginAuthentication>",
  "credential_id":      "<base64url rawId from assertion>",
  "authenticator_data": "<base64url from assertion response>",
  "client_data_json":   "<base64url from assertion response>",
  "signature":          "<base64url DER-encoded ECDSA-P256 signature>"
}
```

**Success response** (`200`):

```json
{ "ok": true, "token": "<Bearer token for iOS app>" }
```

Browser: `Set-Cookie: ntm_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`

**Error response:** `401` with error message.

### `POST /auth/logout`

Invalidates the current session.

**Response** (`200`): `{"ok": true}`. Clears the `ntm_session` cookie.

---

## 8. Demo Session Endpoint

This endpoint is accessible without a passkey session and issues a time-limited
demo token when the operator has enabled demo mode via the admin page.

### `POST /api/demo/begin`

Issues a demo bearer token. No authentication required.

**Request:** empty body.

**Response `200`:**

```json
{
  "ok": true,
  "token": "demo_<32 hex characters>",
  "expires_in": 900
}
```

**Response `503`:** `{"error": "demo is disabled"}` — operator has not enabled demo mode.

The returned token must be sent as `Authorization: Bearer <token>` on subsequent
requests. It grants **read-only access to `/api/summary` only**, which returns
mock traffic data (`"demo": true` in the response). All other endpoints,
especially `/api/admin/*`, return `403` for demo tokens.

Demo tokens expire after `kDemoSessionSec` (900 seconds) from issuance. A new
token can be obtained by calling this endpoint again while demo mode is enabled.

> **Note:** The legacy port-12345 demo server (`kDemoPort`) remains present on
> the server for backward compatibility but is no longer used by the iOS client.
> iOS clients MUST use `POST /api/demo/begin` on the main web server port.

---

## 9. Static Endpoints

### `GET /login`

Serves the embedded passkey login HTML page (WebAuthn mode only). Includes a
"Sign in with Apple (Admin)" button (shown only when `siwa_service_id` is
configured on the server, detected via `GET /api/session`). Redirected to
automatically when an unauthenticated browser visits any protected path.

### `GET /.well-known/apple-app-site-association`

Serves the Apple App Site Association JSON for iOS passkey domain binding.
Only registered when `webauthn_ios_app_id` is configured.

### `GET /.well-known/apple-developer-domain-association.txt` *(api_version 14+)*

Serves the Apple domain-association file required by Sign in with Apple.
Only registered when `siwa_domain_assoc_file` is configured.

---

## 10. Session Info *(api_version 14+)*

### `GET /api/session`

Returns role information for the current session. Accessible without
authentication (returns `role: "none"` for unauthenticated requests). Used by
dashboard JS to conditionally show the Admin link and the Apple sign-in button.

**Response `200`:**

```json
{
  "role":         "admin" | "user" | "none",
  "identity":     "<Apple sub (admin SIWA sessions) or empty>",
  "siwa_enabled": true | false
}
```

`siwa_enabled` is `true` when `siwa_service_id` is configured on the server.

---

## 11. Data Signals (read-only)

### `GET /api/summary`

Returns a full snapshot of aggregated traffic statistics.

**Polling:** Clients should poll every 10–60 seconds (default 30 s). The server
does not push; there is no WebSocket or streaming endpoint.

**Forward compatibility:** Clients must ignore any JSON field they do not
recognise. New optional fields may be added at any `api_version` without a bump.

**Response schema:**

```json
{
  "api_version":              <integer>,  // API contract revision; currently 14
  "server_version":           <string>,   // ntm-server module version, e.g. "2.0.0.0"
  "server_wire_proto_version": <integer>, // wire protocol data-phase version the server speaks
  "window_start":              <integer>, // unix epoch: start of the rolling stats window
  "generated_at":              <integer>, // unix epoch: when this response was built

  "interfaces": [                   // per-NIC totals across all connected clients
    {
      "client":   <string>,         // display name / nickname, or "" for IP-auth clients
      "iface":    <string>,         // interface label (spaces replaced with '-')
      "packets":  <integer>,        // uint64
      "bytes":    <integer>         // uint64
    }
  ],

  "entities": [                     // non-overhead flows only, sorted by bytes descending
    {
      "client":      <string>,      // display name / nickname, or "" for IP-auth clients
      "iface":       <string>,      // interface label
      "src_entity":  <string>,      // resolved: nickname, "LAN (x.x.x.x)", ASN name, …
      "dst_entity":  <string>,
      "packets":     <integer>,     // uint64
      "bytes":       <integer>      // uint64
    }
  ],
  "truncated": <boolean>,           // true when server capped the entities list

  "overhead_entities": [            // monitoring overhead flows (ntm-clients, server, dashboard
                                    // browsers/apps), sorted by bytes descending
    {
      "client":      <string>,
      "iface":       <string>,
      "src_entity":  <string>,
      "dst_entity":  <string>,
      "packets":     <integer>,
      "bytes":       <integer>
    }
  ],
  "truncated_overhead": <boolean>,  // true when server capped the overhead_entities list

  "overhead_summary": {             // aggregate stats for all overhead flows
    "packets":            <integer>,
    "bytes":              <integer>,
    "pct_of_total_bytes": <string>  // formatted "N.NN" — overhead bytes / all bytes × 100
  },

  "entities_lan": [                 // unidentified LAN devices, sorted by total bytes desc
    {
      "ip":          <string>,      // LAN IP of the unknown device
      "reported_by": <string>,      // WAN IP of the reporting client; "" = same subnet
      "out_packets": <integer>,     // uint64
      "out_bytes":   <integer>,     // uint64
      "in_packets":  <integer>,     // uint64
      "in_bytes":    <integer>      // uint64
    }
  ],
  "truncated_lan": <boolean>,

  "client_health": [                // one entry per connected ntm-client
    {
      "client":             <string>,   // display name / nickname
      "client_id":          <string>,   // raw 64-hex Ed25519 public key (stable identity)
      "version":            <string>,   // ntm-client module version; "?" if not yet reported
      "platform":           <string>,   // e.g. "linux-amd64" or "windows-amd64"; "" if unknown
      "pcap_recv":          <integer>,  // uint64: packets delivered by pcap (cumulative session)
      "pcap_drop":          <integer>,  // uint64: packets dropped by kernel pcap ring
      "pcap_drop_pct":      <string>,   // formatted "N.NN" — drop % of pcap total (no % sign)
      "buf_drop":           <integer>,  // uint64: packets dropped by client send-buffer overflow
      "buf_drop_pct":       <string>,   // formatted "N.NN" — buf_drop % of pcap_recv
      "reported_at":        <integer>,  // unix epoch of the last H-line; -1 if never received
      "stale":              <boolean>,  // true if no H-line received in the last 90 s
      // optional — present only after the client's first H-line includes wire_proto=N:
      "wire_proto_version": <integer>,  // data-phase wire protocol version the client reported
      "wire_proto_ok":      <boolean>   // true iff wire_proto_version == server_wire_proto_version
    }
  ],

  "proto_rejected_clients": [       // auth-version-mismatch rejections; capped at 20 most-recent
    {
      "peer_ip":               <string>,  // connecting IP address
      "attempted_auth_version": <integer>, // auth version byte the client sent
      "at":                    <integer>  // unix epoch of the rejection
    }
  ],

  "update_manifest": [              // one entry per platform with a binary in update_dir
    {
      "platform": <string>,         // e.g. "linux-amd64" or "windows-amd64"
      "version":  <string>,         // semver string of the binary in update_dir
      "filename": <string>,         // bare filename (no path)
      "sha256":   <string>          // lowercase hex SHA-256 of the binary
    }
  ]
}
```

**Empty collections** (`[]`) are valid: the server has started but no data has
arrived yet. Clients must handle this without error.

---

## 12. Control Signals (write)

### `POST /api/admin/purge`

Permanently deletes all historical traffic data for one client.

This action is **irreversible**. The iOS app must require explicit user
confirmation before sending this request.

**Authentication:** Admin session required.

**Request body** (`Content-Type: application/json`):

```json
{ "client": "<display name or 64-hex-char client ID>" }
```

**Success response** (`200`):

```json
{
  "ok":        true,
  "client_id": "<resolved 64-char hex client ID>",
  "message":   "client data purged"
}
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `client` field missing |
| `403` | Admin session required |
| `404` | Client name / ID not found in current data |
| `429` | Admin rate limit exceeded (5 req / IP / min) |

### `POST /api/admin/client/register`

Enrolls a new Ed25519 public key so the corresponding `ntm-client` can
immediately authenticate over the wire protocol, **without a server restart**.
The key is appended to the configured `allowed_keys` file for persistence across
restarts.

**Authentication:** Admin session required.

**Request body** (`Content-Type: application/json`):

```json
{
  "pubkey":   "<64 lowercase hex characters — Ed25519 raw public key>",
  "nickname": "<optional human-readable name, max 64 chars>"
}
```

**Field rules:**
- `pubkey`: exactly 64 lowercase hexadecimal characters (32 bytes Ed25519 key).
  Uppercase hex is rejected.
- `nickname`: optional. Maximum 64 characters. Must not contain `|` or any ASCII
  control character (< 0x20). Omit the field or send `""` for no nickname.

**Success response** (`200`):

```json
{
  "ok":        true,
  "client_id": "<the registered 64-hex pubkey>"
}
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `pubkey` not exactly 64 chars, non-lowercase-hex, or invalid nickname |
| `409` | This pubkey is already in the allowed-keys list |
| `500` | Server could not write the `allowed_keys` file (check file permissions) |
| `429` | Admin rate limit exceeded (5 req / IP / min) |

**iOS client workflow:**

1. Generate an Ed25519 key pair (CryptoKit `Curve25519.Signing`); store the
   private key in the standard Keychain.
2. Export the 32-byte raw public key and hex-encode it.
3. POST this endpoint (authenticated with the operator's admin session).
4. After `200`, the iOS app can connect to the wire-protocol port immediately.

---

## 13. Passkey Management *(api_version 14+)*

These endpoints allow the admin to list all registered passkeys and revoke
individual ones. Require admin session.

### `GET /api/admin/passkeys`

**Response `200`:**
```json
{
  "passkeys": [
    {
      "cred_id":    "<base64url credential ID>",
      "label":      "<device name>",
      "sign_count": <integer>
    }
  ]
}
```

### `DELETE /api/admin/passkeys/:credId`

Revoke a specific passkey by credential ID. The credential ID must be URL-encoded
if it contains characters outside the unreserved set.

**Response `200`:** `{"ok": true}`

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `credId` missing |
| `404` | Credential ID not found |

### `GET /api/admin/register/begin`

Start a new passkey registration. No admin password required — admin session is
sufficient. Returns a WebAuthn challenge for `navigator.credentials.create()`.

**Response `200`:**
```json
{
  "session_key": "<opaque pending-session token>",
  "challenge":   "<base64url, 32 random bytes>",
  "rp_id":       "<RP ID>",
  "rp_name":     "<display name>",
  "user_id":     "<base64url, 16 random bytes>"
}
```

### `POST /api/admin/register/complete`

Complete passkey registration. Rate-limited to 5 req / IP / min.

**Request body** (`Content-Type: application/json`):
```json
{
  "session_key":        "<from register/begin>",
  "attestation_object": "<base64url from WebAuthn response>",
  "client_data_json":   "<base64url from WebAuthn response>",
  "label":              "<human-readable device name>"
}
```

**Response `200`:** `{"ok": true}`

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Missing fields, session expired, challenge mismatch, wrong origin |
| `403` | Admin session required |
| `429` | Rate limit exceeded |

---

## 14. Auto-Update Endpoints

These endpoints are used by `ntm-client` to check for and download new binaries.
They are **self-authenticated** via an Ed25519 pubkey query parameter (checked
against `AllowedClientsStore`) and do not require a WebAuthn session cookie or
admin password. They are exempt from the LAN-only source-IP restriction so that
remote clients can reach them.

All four endpoints are only registered when `update_dir` is set in the server config.
`/api/admin/update/*` additionally require admin session.

### `GET /api/update/check`

Check whether a newer binary is available for this client.

**Query parameters:**

| Name | Required | Description |
|---|---|---|
| `pubkey` | yes | 64 lowercase hex chars — client Ed25519 public key |
| `platform` | yes | e.g. `linux-amd64` or `windows-amd64` |
| `version` | yes | client's current version, e.g. `1.9.0` |

**Response `200` — no update:**
```json
{ "update_available": false, "force": false }
```

**Response `200` — update available:**
```json
{
  "update_available": true,
  "force":    false,
  "version":  "1.15.0.0",
  "sha256":   "<64 hex>",
  "filename": "ntm-client-linux-amd64-1.15.0.0",
  "sig_size": 3309
}
```
`sig_size` is the byte length of the `.sig` file for this binary.
Clients that support ML-DSA-65 verification should use this as a sanity-check on
the `/api/update/download_sig` response size.

`force: true` is returned (and the flag is cleared) when an operator has called
`POST /api/admin/update/force` for this client. When `force: true`, the client
downloads and applies the update even if its current version is already up-to-date.

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `pubkey` is not 64 lowercase hex chars |
| `401` | `pubkey` not in AllowedClientsStore |

### `GET /api/update/download`

Download the binary for the requested platform. The client should verify the
SHA-256 against the value from `/api/update/check` before applying.

**Query parameters:**

| Name | Required | Description |
|---|---|---|
| `pubkey` | yes | 64 lowercase hex chars |
| `platform` | yes | e.g. `linux-amd64` |

**Success response `200`:**
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="ntm-client-linux-amd64-1.9.1"`
- Body: binary file bytes

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid pubkey format |
| `401` | pubkey not in AllowedClientsStore |
| `404` | No binary for the requested platform in manifest |

### `POST /api/admin/update/scan`

Re-scan the `update_dir` and rebuild the manifest. Call this after placing new
binaries in the directory. Also runs automatically at server startup.

**Authentication:** Admin session required.

**Request body:** empty (or `{}`).

**Response `200`:**
```json
{ "ok": true, "count": 2 }
```
`count` is the number of distinct platform binaries detected.

### `GET /api/update/download_sig` *(api_version 8+)*

Download the ML-DSA-65 signature file (`.sig`) for the current binary of the
requested platform. The client must verify this signature over the binary bytes
before applying the update.

**Query parameters:**

| Name | Required | Description |
|---|---|---|
| `pubkey` | yes | 64 lowercase hex chars |
| `platform` | yes | e.g. `linux-amd64` |

**Success response `200`:**
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="ntm-client-linux-amd64-1.15.0.0.sig"`
- Body: raw ML-DSA-65 signature bytes (3309 bytes for ML-DSA-65)

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid pubkey format |
| `401` | pubkey not in AllowedClientsStore |
| `404` | No binary / signature for the requested platform |

### `POST /api/admin/update/force`

Flag a specific client for immediate update on its next daily check. The force
flag is cleared once delivered (one-shot). This is useful when the client's
current version already matches the latest in the manifest but an operator wants
to force a reinstall.

**Authentication:** Admin session required.

**Request body** (`Content-Type: application/json`):
```json
{ "pubkey": "<64 hex>" }
```

**Response `200`:**
```json
{ "ok": true }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `pubkey` not exactly 64 chars or invalid |
| `404` | `pubkey` not in AllowedClientsStore |

---

## 15. Server Auto-Upgrade Endpoints

These endpoints allow the Arch Linux build agent to push a new signed ntm-server
binary directly to the live server. They are authenticated via ML-DSA-65
challenge-response (same build key pair used for binary signing) and are only
registered when WebAuthn is configured (`webauthn_rp_id` set).

**Agents MUST NOT call these endpoints autonomously.** The push script
(`scripts/push-upgrade.sh`) requires `--confirm` which must only be supplied
when a human explicitly instructs the push.

### `GET /admin/upgrade/nonce`

Issue a single-use 5-minute nonce for the auth challenge.
Rate-limited to 5 requests/minute per IP.

**Response `200`:**
```json
{ "nonce": "<64 lowercase hex>", "server_version": "2.0.0.0" }
```

**Error responses:** `429` rate limit exceeded; `500` nonce generation failed.

### `POST /admin/upgrade/push`

Push a new signed ntm-server binary. Multipart form upload.
Rate-limited to 1 request/minute per IP.

**Form fields:**

| Field | Type | Description |
|---|---|---|
| `version` | string | New server version, e.g. `2.0.0.0` |
| `nonce` | string | 64-hex nonce from `/admin/upgrade/nonce` |
| `auth_proof` | string | Base64 ML-DSA-65 signature over `nonce_bytes \|\| SHA3-256(binary)` |
| `binary` | file | Raw server binary bytes |
| `signature` | file | ML-DSA-65 `.sig` file for the binary |

**Server-side validation:**
1. Nonce consumed (single-use, 5-minute TTL)
2. Auth proof verified against embedded build public key
3. Binary ML-DSA-65 signature verified
4. Version must be strictly newer than running version (409 if not)
5. Binary + sig atomically replace the running binary
6. Graceful restart scheduled (30 s drain, then `exit(0)` for systemd)

**Response `200`:**
```json
{ "ok": true, "upgraded_to": "2.0.0.0" }
```

**Error responses:** `400` missing field / bad version; `403` auth or sig failure; `409` version not newer; `429` rate limit; `500` write failure.

---

## 16. Client Binary Push Endpoints *(api_version 8+)*

These endpoints allow the Arch Linux build agent to push signed ntm-client
binaries into the server's `update_dir`. Connected clients then receive them
automatically on their next update check. Registered only when both `update_dir`
and `webauthn_rp_id` are configured.

**Agents MUST NOT call these endpoints autonomously.** The push script
(`scripts/push-client.sh`) requires `--confirm` which must only be supplied
when a human explicitly instructs the push.

### `GET /admin/client/nonce`

Issue a single-use 5-minute nonce for the auth challenge.
Rate-limited to 5 requests/minute per IP.

**Response `200`:**
```json
{
  "nonce": "<64 lowercase hex>",
  "platform_versions": {
    "linux-amd64":   "1.21.1.4",
    "windows-amd64": "1.21.1.4"
  }
}
```
`platform_versions` reflects what is currently in `update_dir`. An absent platform
means no binary is present for it yet.

### `POST /admin/client/push`

Push a new signed ntm-client binary into `update_dir`. Multipart form upload.
Rate-limited to 1 request/minute per IP.

**Form fields:**

| Field | Type | Description |
|---|---|---|
| `platform` | string | e.g. `linux-amd64` or `windows-amd64` |
| `version` | string | New client version, e.g. `1.21.1.4` |
| `nonce` | string | 64-hex nonce from `/admin/client/nonce` |
| `auth_proof` | string | Base64 ML-DSA-65 signature over `nonce_bytes \|\| SHA3-256(binary)` |
| `binary` | file | Raw client binary bytes |
| `signature` | file | ML-DSA-65 `.sig` file for the binary |

**Server-side validation:**
1. Nonce consumed (single-use, 5-minute TTL)
2. Auth proof verified against embedded build public key
3. Platform validated (`linux-amd64` or `windows-amd64`)
4. Version string parseable
5. Version must be strictly newer than current in `update_dir` for this platform (409 if not)
6. Binary ML-DSA-65 signature verified
7. Binary + sig written atomically to `update_dir` as `ntm-client-<platform>-<version>[.exe]` + `.sig`
8. `update_dir` housekeeping triggered (old versions and invalid files deleted)

**Response `200`:**
```json
{ "ok": true, "platform": "linux-amd64", "version": "1.21.1.4" }
```

**Error responses:** `400` missing/invalid field; `403` auth or sig failure; `409` version not newer; `429` rate limit; `500` write failure.

---

## 17. Per-Client Traffic History *(api_version 9+)*

### `GET /api/client/history`

Returns per-minute or per-hour in/out traffic buckets for a single connected
(or historically connected) client. Used by the web dashboard to render the
traffic histogram panel when a client is selected.

**Authentication:** Authenticated session required (same as `/api/summary`).

**Rate limit:** 30 requests/IP/minute (shared with general rate limiter).

**Query parameters:**

| Name | Required | Description |
|---|---|---|
| `client_id` | yes | 64 lowercase hex chars — Ed25519 public key (stable client identity) |
| `minutes` | no | Integer 1–1440: return the last N 1-minute buckets (fine ring). Omitted, `0`, or negative: return all hourly buckets across the full retention window (coarse ring). Values > 1440 are clamped to 1440. |

**Fine ring response** (`minutes` in [1, 1440]):

```json
{
  "client_id":      "<64 hex>",
  "bucket_seconds": 60,
  "window_days":    7,
  "buckets": [
    {
      "t":           1716480000,
      "in_bytes":    12345,
      "out_bytes":   67890,
      "in_packets":  42,
      "out_packets": 91
    }
  ]
}
```

`buckets` contains up to `minutes` entries, oldest-first, covering only
non-empty slots (slots that have never been written are omitted). The most
recent bucket is always last in the array.

**Coarse ring response** (`minutes` omitted or ≤ 0):

Same schema with `"bucket_seconds": 3600`. Contains up to 168 hourly buckets
(7 days × 24 hours). Slots that have never been written are omitted; the array
is sorted oldest-first by `t`.

**Direction convention:**

- `in_bytes` / `in_packets`: traffic whose **destination** is a LAN/loopback
  IP and whose **source** is a WAN IP (i.e. inbound to the LAN).
- `out_bytes` / `out_packets`: all other traffic (outbound from the LAN, or
  LAN-to-LAN flows).

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `client_id` is missing or not exactly 64 lowercase hex chars |
| `200` with empty `buckets` | `client_id` is valid but no history data exists for this client |

---

## 18. Admin Hide-Entities Endpoints *(api_version 10+)*

These endpoints allow the operator to hide specific clients or `(client, interface)`
pairs from the main dashboard `/api/summary` response. Hidden entities are
excluded from all sections (`interfaces`, `entities`, `entities_internet`,
`entities_local`, `overhead_entities`, `entities_lan`, `client_health`).

The choice is **persisted** in `hidden_entities_file` (server config key) and
survives server restarts. It applies regardless of whether the hidden client is
currently connected.

All four endpoints require an authenticated admin session. Registered only when
`hidden_entities_file` and `webauthn_rp_id` are both set in server config.

### `GET /api/admin/clients`

Returns all registered clients with their nickname and current connection status.

**Response `200`:**
```json
{
  "clients": [
    {
      "client_id":  "<64 hex>",
      "nickname":   "<display name or empty>",
      "connected":  true
    }
  ]
}
```

### `GET /api/admin/hidden`

Returns the current set of hidden clients and hidden interfaces.

**Response `200`:**
```json
{
  "hidden_clients": ["<hex64>", ...],
  "hidden_interfaces": [
    {"client_id": "<hex64>", "iface": "eth0"},
    ...
  ]
}
```

### `POST /api/admin/hidden/client`

Hide or unhide a client entirely.

**Request body** (`Content-Type: application/json`):
```json
{
  "client_id": "<64 lowercase hex>",
  "action":    "hide" | "unhide"
}
```

**Response `200`:**
```json
{ "ok": true, "hidden": true }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `client_id` is not 64 lowercase hex chars; or `action` is not `hide`/`unhide` |
| `500` | Server could not write the `hidden_entities_file` |

### `POST /api/admin/hidden/interface`

Hide or unhide a specific `(client_id, iface)` pair. The client itself remains
visible in `client_health`; only this interface's traffic rows are suppressed.

**Request body** (`Content-Type: application/json`):
```json
{
  "client_id": "<64 lowercase hex>",
  "iface":     "<interface name, 1–64 chars>",
  "action":    "hide" | "unhide"
}
```

**Response `200`:**
```json
{ "ok": true, "hidden": true }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `client_id` not valid; `iface` empty or > 64 chars; `action` not `hide`/`unhide` |
| `500` | Server could not write the `hidden_entities_file` |

---

## 19. Client Configuration Endpoint *(api_version 11+)*

Returns the running configuration values last reported by a specific client via
`cfg_*` fields in the health line (H-line). This allows operators to verify that
all clients are using the intended configuration without SSH-ing into each machine.

Requires an authenticated admin session. Registered when `webauthn_rp_id` is set
in server config.

### `GET /api/admin/client/config`

**Query parameter:** `client_id=<64 hex>` (required)

**Response `200` (client known, config received):**
```json
{
  "client_id":  "<64 hex>",
  "nickname":   "<display name or empty>",
  "connected":  true,
  "config": {
    "transport":           "tcp",
    "compress":            true,
    "send_buffer":         0,
    "auto_update":         false,
    "reconnect_attempts":  10,
    "reconnect_interval":  60,
    "agg_target_lines":    500,
    "agg_min_ms":          100,
    "agg_max_ms":          5000,
    "agg_max_flows":       10000
  }
}
```

`send_buffer: 0` means OS default. `transport` is `"tcp"` or `"websocket"`.

**Response `200` (client not connected or config not yet received):**
```json
{
  "client_id": "<64 hex>",
  "nickname":  "<display name or empty>",
  "connected": false,
  "config":    null
}
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `client_id` is not 64 lowercase hex chars |

---

## 20. Remote Log Management Endpoints *(api_version 12+)*

These endpoints allow the operator to inspect and control the file-based
logging subsystem of any currently-connected `ntm-client`. Commands are
delivered to the client via the wire-protocol v3 `C`-line channel. The server
blocks (with a timeout) until the client sends back `L`-line responses over
the same TLS connection.

All five endpoints require an authenticated admin session. Registered only when
`webauthn_rp_id` is set in server config. Return `503` if the target client is
not currently connected.

The client identifier `<id>` is the 64-char lowercase-hex Ed25519 public key
(same as `client_id` in `/api/summary` `client_health` entries).

**Timeouts:**
- List, delete, set-level: 5 s from command send to response receipt.
- File download: 60 s.

### `GET /admin/clients/<id>/logs`

Returns the current log level and the list of log files on the client.

**Response `200`:**
```json
{
  "client_id": "<64 hex>",
  "log_level": "Info",
  "file_logging": true,
  "log_dir": "/var/log/ntm-client",
  "files": [
    { "name": "ntm-client-2026-05-30.log", "size": 12976128, "mtime": "2026-05-30" },
    { "name": "ntm-client-2026-05-29.log", "size": 52428800, "mtime": "2026-05-29" }
  ]
}
```
`log_level` is `"Info"`, `"Warn"`, or `"Err"`.
`file_logging: false` means the client started without a writable log directory.

**Error responses:**

| Status | Reason |
|---|---|
| `400` | `<id>` is not 64 lowercase hex chars |
| `404` | Client ID not in AllowedClientsStore |
| `503` | Client not currently connected |
| `504` | Client did not respond within 5 s |

### `POST /admin/clients/<id>/loglevel`

Change the runtime log-verbosity level on the client immediately (no restart needed).

**Request body** (`Content-Type: application/json`):
```json
{ "level": "Warn" }
```

**Response `200`:**
```json
{ "ok": true, "level": "Warn" }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Missing or invalid `level` value (must be `Info`, `Warn`, or `Err`) |
| `404` | Client ID not in AllowedClientsStore |
| `503` | Client not currently connected |
| `504` | Client did not respond within 5 s |

### `GET /admin/clients/<id>/logs/<filename>`

Download a single log file from the client.

**Response `200`:**
- `Content-Type: text/plain`
- `Content-Disposition: attachment; filename="ntm-client-2026-05-30.log"`
- Body: raw log file bytes (reassembled from `L get … chunk` responses).

The server caps the transferred size at 50 MB (the per-file size limit enforced
by the client). `filename` must match a name returned by `GET .../logs`.

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid `<id>` or illegal characters in `filename` |
| `404` | Client ID not found or file not found on client |
| `503` | Client not currently connected |
| `504` | Client did not complete transfer within 60 s |

### `DELETE /admin/clients/<id>/logs/<filename>`

Delete a single log file on the client.

**Response `200`:**
```json
{ "ok": true, "deleted": "ntm-client-2026-05-30.log" }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid `<id>` or illegal `filename` |
| `404` | Client ID not found or file not on client |
| `503` | Client not currently connected |
| `504` | Timeout |

### `DELETE /admin/clients/<id>/logs`

Delete all log files on the client (current day's file excepted — the client
recreates it immediately to capture subsequent log output).

**Response `200`:**
```json
{ "ok": true, "deleted_count": 3 }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid `<id>` |
| `404` | Client ID not found |
| `503` | Client not currently connected |
| `504` | Timeout |

---

## 21. Remote Update Push (admin) *(api_version 13+)*

Requires admin session. All endpoints use the per-client id format (64 lowercase hex chars = Ed25519 pubkey).

### `POST /api/admin/clients/<id>/update`

Push an immediate update to the named client over its established wire
socket. The server allocates a `req_id`, sends `C update_now <req_id>`,
seeds a transient `UpdateStatus` entry, and starts a 10-minute watchdog.

**Request body:** none (client id is in the URL path).

**Response `200`:**
```json
{ "ok": true, "req_id": "a1b2c3d4e5f67890" }
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid `<id>` |
| `404` | Client ID not found in AllowedClientsStore |
| `409` | Client is not currently connected (`client_offline`) |

### `GET /api/admin/clients/<id>/update/status`

Poll for the current update status of the named client.

**Response `200`:**
```json
{
  "req_id": "a1b2c3d4e5f67890",
  "stage": "verifying_signature",
  "started_at": 1717087200,
  "updated_at": 1717087215,
  "finished_at": null,
  "error": null,
  "new_version": null,
  "terminal": false
}
```

Returns `{}` (empty object) if no update has been triggered or the last
terminal entry has expired (5-minute idle TTL). `stage` values match the
`L upd` stage names defined in `docs/wire-protocol.md §5.4`, plus
`sent` (C-line dispatched, ack not yet received) and `timeout`
(10-minute watchdog fired). `terminal` is `true` when the final
outcome is known (done / err / noop / timeout).

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Invalid `<id>` |

---

## 22. Stability Contract

- All fields documented in § 11–21 are **stable at `api_version: 14`**.
  No field will be removed or renamed without a version bump.
- New **optional** fields may be added at any `api_version` without bumping;
  clients must tolerate extra fields.
- Servers at `api_version: 13` (ntm-server < 2.0.0) still have the admin password
  endpoints (`POST /api/admin/auth`, `GET /auth/register/begin`,
  `POST /auth/register/complete`) and the `ntm_admin` proof cookie. Clients on
  `api_version: 14` servers must not use those removed endpoints.
- Servers at `api_version: 3` (ntm < 1.8.0) return all flows in `entities` (no
  overhead separation). Clients receiving `api_version: 3` must treat `entities`
  as all traffic and decode `overhead_entities` as an empty array.
- Servers at `api_version: 1` (ntm < 1.3.0) do not have WebAuthn endpoints.
  A client receiving `api_version: 1` must not call `/auth/*`.
- Servers at `api_version: 2` (ntm < 1.5.0) do not have `/api/admin/client/register`.
  A client receiving `api_version: 2` must fall back to manual key file management.
- Servers at `api_version: 6` (ntm < 1.12.0) do not have auto-update endpoints.
  Clients with `auto_update=true` pointing at such a server will receive a 404
  on `/api/update/check` and disable further checks for that session.
- Servers at `api_version: 7` (ntm-server < 1.19.0) do not have `/api/update/download_sig`
  or the client push endpoints. Clients must not call `download_sig` on such servers;
  the updater falls back to SHA-256-only verification.
- Servers at `api_version: 8` (ntm-server < 1.21.0) do not have `/api/client/history`.
  Web dashboard clients must suppress the histogram panel when `api_version < 9`.
- Servers at `api_version: 9` (ntm-server < 1.22.0) do not have the hide-entities
  endpoints. The admin UI should gracefully handle `404` from `/api/admin/hidden`
  by hiding the Hidden Entities panel.
- Servers at `api_version: 10` (ntm-server < 1.23.0) do not have `/api/admin/client/config`.
  The admin UI should gracefully handle `404` by hiding the Client Configuration panel.
- Servers at `api_version: 11` (ntm-server < 1.25.0) do not have the remote log management
  endpoints (§ 20). The admin UI should gracefully handle `404` by hiding the Logs panel.
- Servers at `api_version: 12` (ntm-server < 1.26.0) do not have the remote update push
  endpoints (§ 21) and still include the `force` field in `/api/update/check` responses.
  The admin UI should gracefully handle `404` from `/api/admin/clients/<id>/update` by
  falling back to the legacy per-client Force button behaviour.
- The protocol doc is updated **before** the commit that changes either side.
