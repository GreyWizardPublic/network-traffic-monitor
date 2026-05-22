# NTM Wire Protocol — Specification v1

**Protocol version:** 1  
**Software version where introduced:** ntm 1.2.0  
**File owner:** This document is the authoritative specification for the TCP data-ingestion
channel between `ntm-client` and `ntm-server`. Update it **before** changing
any message format, field, or connection-lifecycle rule. The same single-commit
rule applies as for `src/version.hpp`.

---

## 1. Overview

`ntm-client` connects to `ntm-server` over TLS-secured TCP and streams packet
observations and health reports. The channel is almost entirely
client-to-server; the server only sends data during the authentication handshake.

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
┌─────────────────────────────┐
│  DATA PHASE  (§ 5)          │  text lines, newline-terminated
│  client → server: X/A/D/H  │  (one-directional after auth)
│  server: silent             │
└────────────┬────────────────┘
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

### 4.1 Message sequence

| Step | Direction | Size | Content |
|---|---|---|---|
| 1 | Client → Server | 1 byte | Auth algorithm version = `kAuthVersionV2` (`0x02`) |
| 2 | Server → Client | 32 bytes | Cryptographically random nonce |
| 3 | Client → Server | 32 bytes | Ed25519 raw public key |
| | Client → Server | 64 bytes | Ed25519 signature (see § 4.2) |
| 4 | Server → Client | 1 byte | `kAuthResultOk` (`0x00`) = accepted **or** `kAuthResultReject` (`0x01`) = rejected |

### 4.2 Signature

```
message = kAuthSignPrefixV2 || nonce
        = "NTM-AUTH-v2" (11 bytes, no NUL) || nonce (32 bytes)
signature = Ed25519_Sign(client_private_key, message)
```

The server verifies using the public key presented in step 3, then checks
that the key is in the allowed-keys file using constant-time comparison.

### 4.3 Client identity

After successful authentication the client's stable identifier is the
lowercase hex encoding of its 32-byte Ed25519 public key (64 hex chars).
This identifier appears in all server-side data structures and dashboard output.

---

## 5. Data phase (text lines)

### 5.1 General rules

- Each message is one **`\n`-terminated UTF-8 line** (LF, 0x0A).
- A CR (`\r`, 0x0D) immediately before `\n` is stripped and ignored.
- Fields within a line are separated by **exactly one ASCII space** (0x20).
- **No spaces are permitted within a field value.**
- The server **never sends** messages during the data phase. The channel is
  unidirectional after auth completes.
- Lines with an **unknown prefix** are silently ignored by the receiver.
  This is the forward-compatibility rule: new line types can be added without
  breaking older servers.
- The server imposes a **receive buffer limit** (`max_recv_buffer_bytes`,
  default 1 MiB). A client that sends a line longer than this limit is
  disconnected immediately.

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
H pcap_recv={N} pcap_drop={N} buf_drop={N} ver={X.Y.Z} wire_proto={N}\n
```

Reports cumulative capture statistics and the client software version for
the current session.

| Key | Type | Description |
|---|---|---|
| `pcap_recv` | decimal uint64 | Packets delivered by pcap since session start |
| `pcap_drop` | decimal uint64 | Packets dropped by the kernel pcap ring since session start |
| `buf_drop` | decimal uint64 | Packets dropped due to client send-buffer overflow |
| `ver` | string | **Module** version of the client software (e.g. `1.2.0`). Independent of the wire protocol version. Each client module (Linux, Windows, iOS) has its own version number. |
| `wire_proto` | decimal uint | The wire protocol data-phase version the client is using (`kWireProtoVersion`). Distinct from the auth version byte. Allows the server to detect data-phase protocol mismatches. |

- Fields are `key=value` pairs separated by spaces.
- **Order is unspecified.** Receivers must not assume order.
- **Unknown keys are ignored.** This allows new fields to be added without
  breaking older receivers.
- Sent by the client every `kHealthIntervalSec` (30 s).
- The server stores the latest values per client and does not accumulate them.
- A client whose last `H` line was received more than 90 s ago is marked
  **stale** in the dashboard.

---

## 6. Protocol versioning

**Wire protocol version** (`kWireProtoVersion`) is an integer in
`src/proto_client_server.hpp`. Current value: **1**.

This version is independent of:
- The ntm software version in `src/version.hpp`.
- The auth algorithm version byte (step 1 of auth phase).
- The Dashboard HTTP API version in `docs/api-protocol.md`.

### Change classification

| Change | Required action |
|---|---|
| Add optional `key=value` field to `H` line | No bump — receivers ignore unknown keys |
| Add new line type with a new single-letter prefix | Bump `kWireProtoVersion`; old servers silently ignore unknown prefixes |
| Change `D`-line field count, field type, or field order | Bump `kWireProtoVersion` |
| Change `X` or `A` line semantics | Bump `kWireProtoVersion` |
| Change auth phase byte layout or signature scheme | Bump `kAuthVersionV2` (the auth algorithm version byte) |
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
| `kWireProtoVersion` | 1 | Wire protocol version |
| `kDefaultPort` | 5555 | Default TCP port |
| `kMaxSessionSeconds` | 21600 | Max session duration (6 h) |
| `kAuthVersionV2` | 0x02 | Auth algorithm version byte |
| `kAuthResultOk` | 0x00 | Server → client: auth accepted |
| `kAuthResultReject` | 0x01 | Server → client: auth rejected |
| `kAuthPubkeyLen` | 32 | Ed25519 public key length (bytes) |
| `kAuthSignatureLen` | 64 | Ed25519 signature length (bytes) |
| `kAuthNonceLen` | 32 | Server nonce length (bytes) |
| `kAuthSignPrefixV2` | `"NTM-AUTH-v2"` | Signature prefix string |
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
