# NTM Wire Protocol — Specification v3

**Protocol version:** 3  
**Software version where introduced:** ntm 1.25.0 (server) / 1.20.0 (client)  
**File owner:** This document is the authoritative specification for the TCP data-ingestion
channel between `ntm-client` and `ntm-server`. Update it **before** changing
any message format, field, or connection-lifecycle rule. The same single-commit
rule applies as for `src/version.hpp`.

---

## 1. Overview

`ntm-client` connects to `ntm-server` over TLS-secured TCP and streams packet
observations and health reports. After the authentication handshake, the channel
is **bidirectional**: the server may send `C` (control) lines to the client, and
the client responds with `L` (log) lines. All other traffic remains
client-to-server only (`D`, `H`, `X`, `A`).

This protocol is **independent** of the Dashboard HTTP API (see
`docs/api-protocol.md`). The two can be versioned and extended separately.

---

## 2. Transport

| Property | Value |
|---|---|
| Layer | TCP over TLS 1.2 (minimum) |
| Default port | 5555 (configurable, `kDefaultPort`) |
| Max session lifetime | 6 hours (`kMaxSessionSeconds = 21600`) |
| Plain TCP | **Forbidden.** Server closes connections that cannot complete TLS. |
| Cert / key | Server presents a PEM certificate and private key. |
| Port sharing | HTTPS dashboard and ntm-client share the same port via TLS ALPN. |

### Port multiplexing via TLS ALPN (RFC 7301)

The server listens on a single port for both the ntm-client data-ingestion
protocol and the HTTPS dashboard. The TLS handshake's ALPN extension
(negotiated before any application bytes are sent) determines which handler
processes the connection:

| ALPN value | Handler |
|---|---|
| `ntm-wire` | Wire-protocol auth + data phase (§ 3–5) |
| `http/1.1` | HTTPS dashboard (API protocol, separate spec) |
| *(none / unrecognised)* | Falls back to `http/1.1` handler |

**Client requirement:** ntm-client **must** advertise `"ntm-wire"` in its
TLS ClientHello ALPN extension. The constant `kAlpnNtmWire = "ntm-wire"` is
defined in `src/proto_client_server.hpp`. A client that omits ALPN will be
routed to the dashboard handler and its wire-protocol auth frame will result
in an HTTP 400 Bad Request, not a meaningful error.

The selection helper `selectAlpnFromClientList()` (also in
`proto_client_server.hpp`) is a pure function with no OpenSSL dependency and
is exercised by `tests/test_alpn.cpp`.

The client optionally pins the server certificate by SHA-256 fingerprint
(`--server-cert`). The server optionally verifies the client identity by
Ed25519 public key (`--allowed-keys`).

After `kMaxSessionSeconds`, the server closes the connection. The client must
reconnect and re-authenticate. Reconnect behaviour (attempts, interval) is
client-side policy and not part of the wire protocol.

---

## 3. Connection lifecycle

```
TCP + TLS handshake
        │
        ▼
┌─────────────────────────────┐
│  AUTH PHASE  (§ 4)          │  binary, fixed-width frames
│  client → server: version   │
│  server → client: nonce     │
│  client → server: pubkey+sig│
│  server → client: result    │
└────────────┬────────────────┘
             │ result = 0x00 (accepted)
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  DATA PHASE  (§ 5)          │  text lines, newline-terminated   │
│  client → server: X/A/D/H  │  (client upload stream)           │
│  server → client: C        │  (control commands; § 5.3)        │
│  client → server: L        │  (log responses; § 5.4)           │
└────────────┬────────────────────────────────────────────────────┘
             │ session expires / disconnect
             ▼
           CLOSE
```

On auth rejection the server sends `kAuthResultReject` (`0x01`) and closes
immediately. The client should not retry authentication on the same connection.

---

## 4. Auth phase (binary)

Client authentication is **mandatory** when the server has `allowed_keys`
configured (which is required). All byte counts are exact; no length prefixes.

Two auth versions are supported. New clients use **v3** (which adds capability
exchange and enables optional zlib compression). Old v2 clients are still
accepted by new servers but receive no compression.

### 4.1 Message sequence — auth v3 (current)

| Step | Direction | Size | Content |
|---|---|---|---|
| 1 | Client → Server | 1 byte | Auth algorithm version = `kAuthVersionV3` (`0x03`) |
| 2 | Server → Client | 32 bytes | Cryptographically random nonce |
| 3 | Client → Server | 32 bytes | Ed25519 raw public key |
| | Client → Server | 64 bytes | Ed25519 signature (see § 4.2) |
| | Client → Server | 1 byte | Client capability flags (see § 4.4) |
| 4 | Server → Client | 1 byte | `kAuthResultOk` (`0x00`) = accepted **or** `kAuthResultReject` (`0x01`) = rejected |
| 5 | Server → Client | 1 byte | Negotiated capability flags (**only sent when result = `0x00`**) |

### 4.1b Message sequence — auth v2 (legacy, still accepted)

| Step | Direction | Size | Content |
|---|---|---|---|
| 1 | Client → Server | 1 byte | Auth algorithm version = `kAuthVersionV2` (`0x02`) |
| 2 | Server → Client | 32 bytes | Cryptographically random nonce |
| 3 | Client → Server | 32 bytes | Ed25519 raw public key |
| | Client → Server | 64 bytes | Ed25519 signature |
| 4 | Server → Client | 1 byte | `kAuthResultOk` / `kAuthResultReject` |

No capability exchange in v2; the data phase always runs uncompressed.

### 4.2 Signature

```
message = kAuthSignPrefixV2 || nonce
        = "NTM-AUTH-v2" (11 bytes, no NUL) || nonce (32 bytes)
signature = Ed25519_Sign(client_private_key, message)
```

The same message format is used for both v2 and v3.
The server verifies using the public key presented in step 3, then checks
that the key is in the allowed-keys file using constant-time comparison.

### 4.3 Client identity

After successful authentication the client's stable identifier is the
lowercase hex encoding of its 32-byte Ed25519 public key (64 hex chars).
This identifier appears in all server-side data structures and dashboard output.

### 4.4 Capability flags (auth v3 only)

A 1-byte bit-field sent by the client (step 3) and echoed masked by the server (step 5).
The server sets only bits that it supports; the client must respect the negotiated value.

| Bit | Constant | Meaning |
|---|---|---|
| 0 | `kCapZlib` (`0x01`) | zlib deflate compression on the data phase |
| 1–7 | — | Reserved; must be 0 |

**Negotiation rule**: server accepts bit N if and only if both client and server support it.
The client must not compress unless bit 0 is set in the server's negotiated caps byte.

**Windows client**: always sends `kCapNone` (`0x00`) regardless of config — the Windows binary
does not link zlib. The server responds with `0x00` and the data phase is uncompressed.

### 4.5 zlib data-phase compression

When `kCapZlib` is negotiated:
- **Client** wraps every write to the data-phase SSL stream with `deflate(Z_SYNC_FLUSH)`.
  Each write (H-line, D-line batch, X/A announce) is flushed to a deflate block boundary
  so the server can decompress incrementally without waiting for more data.
- **Server** inflates every chunk received from `SSL_read` before feeding it to the
  line-parsing buffer. The inflate context is persistent across multiple `SSL_read` calls.
- The zlib streams are **not reset** between message types; compression improves as the
  dictionary fills up with the repetitive IP-address and line-prefix text.
- On reconnect the client creates a new `ZlibDeflater`; the server creates a new
  `ZlibInflater` after each re-authentication.

---

## 5. Data phase (text lines)

### 5.1 General rules

- Each message is one **`\n`-terminated UTF-8 line** (LF, 0x0A).
- A CR (`\r`, 0x0D) immediately before `\n` is stripped and ignored.
- Fields within a line are separated by **exactly one ASCII space** (0x20).
- **No spaces are permitted within a field value.**
- The data phase is **bidirectional**: the server may send `C` lines; the
  client responds with `L` lines. All other line types (`D`, `H`, `X`, `A`)
  remain client-to-server only.
- Lines with an **unknown prefix** are silently ignored by the receiver.
  This is the forward-compatibility rule: new line types can be added without
  breaking older implementations.
- The server imposes a **receive buffer limit** (`max_recv_buffer_bytes`,
  default 1 MiB). A client that sends a line longer than this limit is
  disconnected immediately.
- **Thread safety on the socket**: once the data phase begins, only one
  goroutine/thread may write to the socket at a time. The server uses a
  per-connection write mutex before sending `C` lines; clients must likewise
  serialize their writes across the sender thread and any log-response thread.

### 5.2 Message types

#### `X` — WAN IP announce

```
X {ip|null}\n
```

Announces the client's public internet-facing IP address (as seen by an
external check service) or the literal `null` when unreachable.

- Must be sent **before** any `A` lines in the same announce round.
- Atomically resets the client's IP-to-identity registry on the server
  (all previously registered LAN IPs are discarded).
- `ip` must be a valid IPv4 or IPv6 address literal, or the literal `null`
  (constant `kExtIPNull`).
- **Rate-limited** to one accepted `X` per `kAnnounceRateLimitSec` seconds
  (30 s) per connection. Excess `X` lines within that window are silently
  ignored.

Sent by the client on: initial connect, any network topology change detected
by the OS, and every `kMaxSessionSeconds` (session renewal).

#### `A` — LAN address announce

```
A {ip}\n
```

Registers one of the client's local interface addresses with the server, so
the server can attribute traffic from this IP to this client's stable identity.

- Must follow an `X` line in the same announce round.
- One line per local interface address.
- Maximum `kMaxAnnounceAddressesPerSession` (64) addresses per announce round;
  excess lines are silently dropped.
- `ip` must be a valid LAN address (RFC 1918, loopback, or link-local).
- Maximum field length: `kMaxIpLabelLen` (50) bytes.

#### `D` — Packet observation

```
D {iface} {src_ip} {dst_ip} {bytes}\n
```

Reports one captured packet observation.

| Field | Type | Constraint |
|---|---|---|
| `iface` | string | Interface label; max `kMaxIfaceLabelLen` (64) bytes; **no spaces** — replace with `-` |
| `src_ip` | string | IPv4 or IPv6 literal; max `kMaxIpLabelLen` (50) bytes |
| `dst_ip` | string | IPv4 or IPv6 literal; max `kMaxIpLabelLen` (50) bytes |
| `bytes` | decimal | uint32 (0–4,294,967,295); packet size in bytes |

Server enforcement:
- **Rate limit:** `max_d_lines_per_second_per_connection` (default 20,000) D-lines
  per second per connection; excess lines within the second are silently dropped.
- **Interface cap:** `max_ifaces_per_client` (default 256) distinct `iface` values
  per client; D-lines with a new `iface` beyond this cap are silently dropped.
- Lines that fail field-count, length, or parse validation are silently dropped.

#### `H` — Health heartbeat

```
H pcap_recv={N} pcap_drop={N} buf_drop={N} ver={X.Y.Z} wire_proto={N} [agg_interval_ms={N} agg_flows={N}]\n
```

Reports cumulative capture statistics, the client software version, and
(when flow aggregation is active) aggregation metrics for the current session.

| Key | Type | Description |
|---|---|---|
| `pcap_recv` | decimal uint64 | Packets delivered by pcap since session start |
| `pcap_drop` | decimal uint64 | Packets dropped by the kernel pcap ring since session start |
| `buf_drop` | decimal uint64 | Packets dropped due to client send-buffer overflow |
| `ver` | string | **Module** version of the client software (e.g. `1.10.0`). Independent of the wire protocol version. Each client module (Linux, Windows, iOS) has its own version number. |
| `wire_proto` | decimal uint | The wire protocol data-phase version the client is using (`kWireProtoVersion`). Distinct from the auth version byte. Allows the server to detect data-phase protocol mismatches. |
| `agg_interval_ms` | decimal uint32 | **Optional.** Current flow-aggregation flush interval in milliseconds, as determined by the adaptive controller. Absent (or 0) for clients that do not implement aggregation. |
| `agg_flows` | decimal uint32 | **Optional.** Number of unique (iface, src, dst) flows flushed in the most recent aggregation window. Absent (or 0) for non-aggregating clients. |

The `agg_interval_ms` and `agg_flows` fields are emitted by clients that implement
adaptive flow aggregation (ntm-client ≥ 1.10.0). The server displays an approximate
output rate (`agg_flows / (agg_interval_ms / 1000)` flows/s) in the dashboard when
both fields are present and non-zero.

- Fields are `key=value` pairs separated by spaces.
- **Order is unspecified.** Receivers must not assume order.
- **Unknown keys are ignored.** This allows new fields to be added without
  breaking older receivers.
- Sent by the client every `kHealthIntervalSec` (30 s).
- The server stores the latest values per client and does not accumulate them.
- A client whose last `H` line was received more than 90 s ago is marked
  **stale** in the dashboard.

### 5.3 `C` — Server control command (server → client)

```
C <command> [args…]\n
```

Sent by the server to instruct the client to perform a log-management action.
The client must respond with one or more `L` lines (§ 5.4) on the same TLS
connection.

`<req_id>` (used by most commands) is an opaque ASCII token (≤ 32 printable
non-space characters) generated by the server. The client echoes it in every
`L` response so the server can pair concurrent admin requests.

| Command | Arguments | Description |
|---|---|---|
| `set_loglevel` | `<Info\|Warn\|Err>` | Set the runtime log-verbosity level immediately. Client responds with `L ack set_loglevel`. |
| `log_list` | `<req_id>` | List all log files in the client's log directory. |
| `log_get` | `<req_id> <filename>` | Transfer a single log file to the server (base64-chunked). |
| `log_delete` | `<req_id> <filename>` | Delete a single log file. |
| `log_delete_all` | `<req_id>` | Delete all log files. |
| `update_now` | `<req_id>` | Trigger an immediate binary self-update check (wire-proto v4). |

Unknown `C` commands MUST be silently ignored by the client (forward compatibility).

### 5.4 `L` — Client log response (client → server)

```
L <response_type> [fields…]\n
```

Sent by the client in response to `C` commands. Fields are space-separated;
no field value may contain a space.

#### `L ack set_loglevel`
```
L ack set_loglevel <Info|Warn|Err>
```
Immediate acknowledgement that the log level has been applied. Echoes back the
new level so the server can confirm the change took effect.

#### `L list` — file listing response
```
L list <req_id> begin <count>
L list <req_id> file <name> <size_bytes> <mtime_iso>
…  (one per file, sorted newest first)
L list <req_id> end
```
`<name>` — bare filename (no path), no spaces. `<size_bytes>` — decimal bytes.
`<mtime_iso>` — last-modified time as `YYYY-MM-DD` (date only, local time).

#### `L get` — file transfer response
```
L get <req_id> begin <name> <total_bytes> <sha256_hex>
L get <req_id> chunk <base64_data>
…  (repeated; each chunk ≤ 32 KiB raw before base64 encoding)
L get <req_id> end
```
The server reassembles and verifies SHA-256 of the concatenated raw bytes.

#### `L del` / `L del_all` — delete acknowledgement
```
L del     <req_id> ok  <filename>
L del     <req_id> err <filename> <reason>
L del_all <req_id> ok  <count_deleted>
```

#### `L err` — generic error
```
L err <req_id> <code> <message>
```
Returned for any command that fails before a more specific response.
`<code>` is a short ASCII code, e.g. `not_found`, `io_error`, `timeout`.

#### `L upd` — binary update progress (wire-proto v4)

Sent by the client in response to a `C update_now <req_id>` command. Each
line represents one observable stage transition; the server updates its
per-client `UpdateStatus` map after receiving each line.

```
L upd <req_id> ack
L upd <req_id> stage <stage_name>
L upd <req_id> noop <reason>
L upd <req_id> err <stage_name> <message>
L upd <req_id> done <new_version>
```

**Stage names** (fixed, lower-snake):
`checking`, `downloading_binary`, `verifying_sha256`, `downloading_signature`,
`verifying_signature`, `applying`, `restarting`.

**`noop` reasons:** `already_current`, `no_update_available`, `in_progress`
(a periodic or server-pushed update cycle is already running).

**`err` stage_name** is one of the stage names above, plus `network` (HTTP
connection failure), `disk` (I/O failure), or `exec` (applies to
`execv`/`MoveFileExW` failure after the binary is in place).

Terminal lines (`done`, `noop`, `err`) signal the server to mark the
request as complete. A server-side 10-minute watchdog timer fires if no
terminal line arrives, and the admin UI shows `timeout`.

---

## 6. Protocol versioning

**Wire protocol version** (`kWireProtoVersion`) is an integer in
`src/proto_client_server.hpp`. Current value: **4**.

This version is independent of:
- The ntm software version in `src/version.hpp`.
- The auth algorithm version byte (step 1 of auth phase).
- The Dashboard HTTP API version in `docs/api-protocol.md`.

### Change classification

| Change | Required action |
|---|---|
| Add optional `key=value` field to `H` line | No bump — receivers ignore unknown keys |
| Add new line type with a new single-letter prefix | Bump `kWireProtoVersion`; old implementations silently ignore unknown prefixes |
| Change `D`-line field count, field type, or field order | Bump `kWireProtoVersion` |
| Change `X` or `A` line semantics | Bump `kWireProtoVersion` |
| Add new auth algorithm version (new `kAuthVersionVN`) | Bump `kWireProtoVersion` |
| Change the capability bit definitions | Bump `kWireProtoVersion` |
| Remove any existing line type | Bump `kWireProtoVersion` |

### Version negotiation (future)

Currently there is no in-band protocol version negotiation in the data phase.
The auth phase version byte (`kAuthVersionV2`) can be extended: a future client
can advertise a higher auth version; the server can accept or reject.

If wire-level negotiation becomes necessary, the auth handshake can be extended
after step 4 with a wire-protocol version exchange before transitioning to the
data phase. This extension is a `kWireProtoVersion` bump.

---

## 7. Protocol constants (reference)

All constants are defined in `src/proto_client_server.hpp`.

| Constant | Value | Description |
|---|---|---|
| `kWireProtoVersion` | 4 | Wire protocol version |
| `kDefaultPort` | 5555 | Default TCP port |
| `kMaxSessionSeconds` | 21600 | Max session duration (6 h) |
| `kAuthVersionV2` | 0x02 | Auth algorithm version byte (legacy, no compression) |
| `kAuthVersionV3` | 0x03 | Auth algorithm version byte (v3, with capability exchange) |
| `kAuthResultOk` | 0x00 | Server → client: auth accepted |
| `kAuthResultReject` | 0x01 | Server → client: auth rejected |
| `kCapNone` | 0x00 | Capability flags: no optional features |
| `kCapZlib` | 0x01 | Capability flags: zlib deflate on data phase (bit 0) |
| `kAuthPubkeyLen` | 32 | Ed25519 public key length (bytes) |
| `kAuthSignatureLen` | 64 | Ed25519 signature length (bytes) |
| `kAuthNonceLen` | 32 | Server nonce length (bytes) |
| `kAuthSignPrefixV2` | `"NTM-AUTH-v2"` | Signature prefix string (used in both v2 and v3) |
| `kMaxIfaceLabelLen` | 64 | Max iface field length in D-lines (bytes) |
| `kMaxIpLabelLen` | 50 | Max IP field length in D/A/X lines (bytes) |
| `kMaxAnnounceAddressesPerSession` | 64 | Max A-lines per announce round |
| `kAnnounceRateLimitSec` | 30 | Min seconds between accepted X-lines |
| `kHealthIntervalSec` | 30 | Client health heartbeat interval (s) |
| `kDataLinePrefix` | `"D "` | D-line prefix |
| `kHealthLinePrefix` | `"H "` | H-line prefix |
| `kExtIPLinePrefix` | `"X "` | X-line prefix |
| `kAddrLinePrefix` | `"A "` | A-line prefix |
| `kExtIPNull` | `"null"` | X-line sentinel for unreachable WAN IP |
