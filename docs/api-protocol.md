# NTM Dashboard API Protocol — Specification v1

**API version:** 1  
**Software version where introduced:** ntm 1.2.0  
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
| Network scope | **LAN IPs only.** The server rejects requests from non-RFC-1918 / non-loopback source addresses with `403`. |
| Certificate | Same cert/key as the client ingestion port. Clients may pin by SHA-256 fingerprint. |

---

## 3. Authentication

Bearer token authentication is **optional**. When a token is configured on the
server (`web_token`), every request must include:

```
Authorization: Bearer <token>
```

Missing or incorrect token → `401` with `WWW-Authenticate: Bearer realm="ntm"`.

When no token is configured the API is accessible to any LAN client.

**iOS app:** The bearer token is stored in the iOS Keychain, never in
`UserDefaults` or application logs.

---

## 4. Rate Limiting

| Endpoint group | Limit |
|---|---|
| All endpoints | 60 requests / IP / minute |
| `POST /api/admin/purge` | 5 requests / IP / minute |

Exceeded → `429` with `Retry-After: 60`.

---

## 5. API Versioning

Every response from `/api/summary` includes:

```json
"api_version": 1
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
| `400` | Malformed request body (missing required fields) |
| `401` | Missing or incorrect bearer token / admin password |
| `403` | Request source IP is not in LAN range |
| `404` | Resource not found (e.g. unknown client ID on purge) |
| `429` | Rate limit exceeded |

### Security headers (on every response)

```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

---

## 7. Data Signals (read-only)

### `GET /api/summary`

Returns a full snapshot of aggregated traffic statistics.

**Polling:** Clients should poll every 10–60 seconds (default 30 s). The server
does not push; there is no WebSocket or streaming endpoint.

**Forward compatibility:** Clients must ignore any JSON field they do not
recognise. New optional fields may be added at any `api_version` without a bump.

**Response schema:**

```json
{
  "api_version":    <integer>,      // API contract revision; starts at 1
  "server_version": <string>,       // ntm software version, e.g. "1.2.0"
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

## 8. Control Signals (write)

### `POST /api/admin/purge`

Permanently deletes all historical traffic data for one client. The admin UI
is **only available** when the server has `admin_password_file` configured.

This action is **irreversible**. The iOS app must require explicit user
confirmation before sending this request.

**Authentication:** The request body contains the admin password (distinct from
the bearer token). Both must be correct if both are configured.

**Request body** (`Content-Type: application/json`):

```json
{
  "password": "<admin password>",
  "client":   "<display name or 64-hex-char client ID>"
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
| `400` | `password` or `client` field missing from body |
| `401` | Wrong admin password |
| `404` | Client name / ID not found in current data |
| `429` | Admin rate limit exceeded (5 req / IP / min) |

---

## 9. Stability Contract

- All fields documented in § 7 and § 8 are **stable at `api_version: 1`**.
  No field will be removed or renamed without a version bump.
- New **optional** fields may be added at any `api_version` without bumping;
  clients must tolerate extra fields.
- Servers built before ntm 1.2.0 do not emit `api_version`. A missing
  `api_version` field must be treated as version 1 by clients.
- The protocol doc is updated **before** the commit that changes either side.
