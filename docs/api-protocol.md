# NTM Dashboard API Protocol — Specification v3

**API version:** 3  
**Software version where introduced:** ntm 1.5.0  
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
| Network scope | **WebAuthn mode**: no source-IP restriction (authenticated by passkey session). **Legacy mode**: LAN IPs only; requests from non-RFC-1918 / non-loopback addresses → `403`. |
| Certificate | Same cert/key as the client ingestion port. |

---

## 3. Authentication

Two authentication modes exist depending on server configuration:

### 3a. WebAuthn passkey mode (recommended)

Enabled when `webauthn_rp_id` is set in the server config. All endpoints
(except `/login`, `/auth/*`, and `/.well-known/apple-app-site-association`)
require a valid session.

**Browser:** session established via the `/login` page; server sets an
`HttpOnly; Secure; SameSite=Strict` cookie `ntm_session=<token>`.

**iOS app:** session token returned as JSON from `/auth/login/complete`;
sent in subsequent requests as `Authorization: Bearer <token>`.

Unauthenticated browser GET requests → `302` redirect to `/login`.  
Unauthenticated API requests → `401`.

### 3b. Legacy bearer-token mode

If `webauthn_rp_id` is **not** set and `web_token` is configured, every
request must include:

```
Authorization: Bearer <token>
```

Missing or incorrect token → `401` with `WWW-Authenticate: Bearer realm="ntm"`.

When neither is configured the API is accessible to any LAN client.

---

## 4. Rate Limiting

| Endpoint group | Limit |
|---|---|
| All endpoints | 30 requests / IP / minute |
| `POST /auth/register/complete` | 5 requests / IP / minute (admin rate limit) |
| `POST /api/admin/purge` | 5 requests / IP / minute |
| `POST /api/admin/client/register` | 5 requests / IP / minute |

Exceeded → `429` with `Retry-After: 60`.

---

## 5. API Versioning

Every response from `/api/summary` includes:

```json
"api_version": 3
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
| `302` | Redirect to `/login` (unauthenticated browser request, WebAuthn mode) |
| `400` | Malformed request body (missing required fields) |
| `401` | Authentication required or failed |
| `403` | Request source IP is not in LAN range (legacy mode only) |
| `404` | Resource not found (e.g. unknown client ID on purge) |
| `429` | Rate limit exceeded |

### Security headers (on every response)

```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

---

## 7. Authentication Endpoints (WebAuthn mode only)

These endpoints are always accessible without a session (they establish one).

### `GET /auth/register/begin`

Starts passkey registration. Returns a server challenge and PBKDF2 parameters
for the admin proof step. The admin proof ensures that only the operator (who
knows the admin password) can register new passkeys.

**Response** (`200`):

```json
{
  "session_key":       "<opaque pending-session token>",
  "challenge":         "<base64url, 32 random bytes — WebAuthn challenge>",
  "admin_nonce":       "<base64url, 32 random bytes — nonce for PBKDF2 proof>",
  "pbkdf2_salt":       "<base64url, 16 bytes>",
  "pbkdf2_iterations": 200000,
  "rp_id":             "<RP ID, e.g. ntm.happyhomelives.me>",
  "rp_name":           "<display name>",
  "user_id":           "<base64url, 16 random bytes>"
}
```

The client computes the admin proof as follows (never transmitting the password):

```
key   = PBKDF2-HMAC-SHA256(adminPassword, pbkdf2_salt, pbkdf2_iterations)  // 32 bytes
proof = HMAC-SHA256(key, admin_nonce)  // 32 bytes, hex-encoded
```

### `POST /auth/register/complete`

Completes passkey registration.

**Request body** (`Content-Type: application/json`):

```json
{
  "session_key":        "<from beginRegistration>",
  "admin_proof":        "<64-hex-char HMAC-SHA256 proof>",
  "attestation_object": "<base64url from WebAuthn response>",
  "client_data_json":   "<base64url from WebAuthn response>",
  "label":              "<human-readable device name>"
}
```

**Success response** (`200`): `{"ok": true}`

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Missing fields, session expired, challenge mismatch, wrong origin, CBOR parse error |
| `400` | Admin proof incorrect |
| `429` | Rate limit exceeded |

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
browser and returns the Bearer token for the iOS app.

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

## 8. Static Endpoints

### `GET /login`

Serves the embedded passkey login and device-registration HTML page (WebAuthn
mode only). Redirected to automatically when an unauthenticated browser visits
any protected path.

### `GET /.well-known/apple-app-site-association`

Serves the Apple App Site Association JSON for iOS passkey domain binding.
Only registered when `webauthn_ios_app_id` is configured.

---

## 9. Data Signals (read-only)

### `GET /api/summary`

Returns a full snapshot of aggregated traffic statistics.

**Polling:** Clients should poll every 10–60 seconds (default 30 s). The server
does not push; there is no WebSocket or streaming endpoint.

**Forward compatibility:** Clients must ignore any JSON field they do not
recognise. New optional fields may be added at any `api_version` without a bump.

**Response schema:**

```json
{
  "api_version":    <integer>,      // API contract revision; currently 3
  "server_version": <string>,       // ntm software version, e.g. "1.3.0"
  "window_start":   <integer>,      // unix epoch: start of the rolling stats window
  "generated_at":   <integer>,      // unix epoch: when this response was built

  "interfaces": [                   // per-NIC totals across all connected clients
    {
      "client":   <string>,         // display name / nickname, or "" for IP-auth clients
      "iface":    <string>,         // interface label (spaces replaced with '-')
      "packets":  <integer>,        // uint64
      "bytes":    <integer>         // uint64
    }
  ],

  "entities": [                     // top traffic flows, sorted by bytes descending
    {
      "client":      <string>,
      "iface":       <string>,
      "src_entity":  <string>,      // resolved: nickname, "LAN (x.x.x.x)", ASN name, …
      "dst_entity":  <string>,
      "packets":     <integer>,     // uint64
      "bytes":       <integer>      // uint64
    }
  ],
  "truncated": <boolean>,           // true when server capped the entities list

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
      "client":         <string>,   // display name / nickname
      "version":        <string>,   // ntm-client software version; "?" if not yet reported
      "pcap_recv":      <integer>,  // uint64: packets delivered by pcap (cumulative session)
      "pcap_drop":      <integer>,  // uint64: packets dropped by kernel pcap ring
      "pcap_drop_pct":  <string>,   // formatted "N.NN" — drop % of pcap total (no % sign)
      "buf_drop":       <integer>,  // uint64: packets dropped by client send-buffer overflow
      "buf_drop_pct":   <string>,   // formatted "N.NN" — buf_drop % of pcap_recv
      "reported_at":    <integer>,  // unix epoch of the last H-line; -1 if never received
      "stale":          <boolean>   // true if no H-line received in the last 90 s
    }
  ]
}
```

**Empty collections** (`[]`) are valid: the server has started but no data has
arrived yet. Clients must handle this without error.

---

## 10. Control Signals (write)

### `POST /api/admin/purge`

Permanently deletes all historical traffic data for one client. Available when
`admin_password_file` or `webauthn_rp_id` is configured.

This action is **irreversible**. The iOS app must require explicit user
confirmation before sending this request.

**Authentication:**
- **WebAuthn mode**: session required (verified by pre-routing). No additional password needed.
- **Legacy mode**: request body must contain `password` matching the configured admin password.

**Request body** (`Content-Type: application/json`):

```json
{
  "client":   "<display name or 64-hex-char client ID>",
  "password": "<admin password>"   // required in legacy mode only
}
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
| `400` | `client` field missing; or `password` missing (legacy mode) |
| `401` | Wrong admin password (legacy mode) |
| `404` | Client name / ID not found in current data |
| `429` | Admin rate limit exceeded (5 req / IP / min) |

### `POST /api/admin/client/register`

Enrolls a new Ed25519 public key so the corresponding `ntm-client` can
immediately authenticate over the wire protocol, **without a server restart**.
The key is appended to the configured `allowed_keys` file for persistence across
restarts. Available when `admin_password_file` or `webauthn_rp_id` is
configured **and** `allowed_keys` is set in the server config.

**Authentication:** same as `/api/admin/purge`.

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
3. POST this endpoint (authenticated with the operator's passkey session).
4. After `200`, the iOS app can connect to the wire-protocol port immediately.

---

## 11. Stability Contract

- All fields documented in § 9 and § 10 are **stable at `api_version: 3`**.
  No field will be removed or renamed without a version bump.
- New **optional** fields may be added at any `api_version` without bumping;
  clients must tolerate extra fields.
- Servers at `api_version: 1` (ntm < 1.3.0) do not have WebAuthn endpoints.
  A client receiving `api_version: 1` must not call `/auth/*`.
- Servers at `api_version: 2` (ntm < 1.5.0) do not have `/api/admin/client/register`.
  A client receiving `api_version: 2` must fall back to manual key file management.
- The protocol doc is updated **before** the commit that changes either side.
