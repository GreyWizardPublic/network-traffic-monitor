# Network Traffic Monitor

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

A self-hosted, multi-client network traffic aggregation system written in C++17.
See [`LICENSE`](LICENSE) for project source license (GPL-3.0-or-later) and
[`LICENSES.md`](LICENSES.md) for third-party / system / data licenses.

For full step-by-step production deployment guides (TLS, Ed25519 auth, systemd, hardening):
- Server: [`SERVER_DEPLOYMENT.md`](SERVER_DEPLOYMENT.md)
- Client: [`CLIENT_DEPLOYMENT.md`](CLIENT_DEPLOYMENT.md)

Headless, extensible **client–server network traffic monitor** written in **C++**.

- **Client (`ntm-client`)**: runs on devices, captures packets via `libpcap`, and sends **metadata only** to the server.
- **Server (`ntm-server`)**: runs as a headless aggregator, maintaining per-interface, per-flow, and per-entity aggregates. Includes an embedded **HTTPS web dashboard** accessible from any browser on your LAN.

Both binaries can run either in the **foreground** (for debugging) or as **Unix daemons**.

> **Note:** Capturing packets typically requires root privileges or appropriate capabilities on your network interfaces.

## Architecture

- **ntm-client**
  - Discovers local interfaces using `pcap_findalldevs`.
  - Captures IPv4 and IPv6 packets on each interface.
  - For each packet, sends a single-line record to the server:
    - Format: `D iface src_ip dst_ip bytes\n`
  - No GUI; intended to be portable to other platforms by re-implementing the capture and TCP send logic.

- **ntm-server**
  - Listens on one **client data-ingestion TCP port** (default `5555`) for `ntm-client` connections.
  - Optional **Ed25519 authentication**: when started with `--allowed-keys FILE`, each connecting client must prove identity with an Ed25519 key; the server uses the public key as the client identifier in aggregation.
  - Consumes `D ...` data lines from clients and aggregates:
    - Per-interface totals (packets, bytes).
    - Per-flow `(src IP, dst IP)`.
    - Per-country `(src country, dst country)` resolved against a local IP→ASN/country database.
    - Per-entity `(src entity, dst entity)` (ASN + organisation name) resolved against the same database.
  - **Aggregation** uses a **rolling window by day** (configurable, default 7 days). When the window is exceeded, only the oldest day's data is dropped. Counters use `uint64_t`; if any counter would overflow for a client, all statistics for that client are reset — other clients are unaffected.
  - Serves an embedded **HTTPS web dashboard** (default port `8443`) — see [Web Dashboard](#web-dashboard).
  - Prints periodic summaries to stderr in foreground mode.

## Prerequisites

- A C++17-compatible compiler (e.g. `g++` or `clang++`)
- CMake 3.16+
- **OpenSSL** (libssl + libcrypto) for TLS and Ed25519 (OpenSSL 1.1.1+; on Arch: `pacman -S openssl`)
- **libcurl** for the server's auto-update of the IP database (on Arch: `pacman -S curl`)
- **zlib** for reading the gzipped IP database (on Arch: usually preinstalled; `pacman -S zlib`)
- `libpcap` and its development headers (on Arch: `pacman -S libpcap`)
- **No libmaxminddb required.** The server uses an embedded `IPRangeResolver` that consumes the **iptoasn.com** combined IPv4+IPv6 dataset (gzipped TSV, CC0 public domain). On startup the server loads the local cache file at `ip_db_path` (default `/var/lib/ntm-server/ip2asn-combined.tsv.gz`) and a background thread re-downloads it every `ip_db_update_interval_days` (default 7).
- **cpp-httplib** is **vendored** at `src/httplib.h` (single header, MIT). No separate installation needed.
- Ability to run the client with sufficient privileges for packet capture.

## Build

From the project root:

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

This produces two binaries in `build/`:

- `ntm-server`
- `ntm-client`

> For a full breakdown of every linked library and external data source, with
> SPDX identifiers and upstream URLs, see [`LICENSES.md`](LICENSES.md).

## Web Dashboard

`ntm-server` includes an embedded HTTPS web dashboard. Open it in any browser
on your LAN — no extra software required.

### Authentication modes

**WebAuthn passkey authentication** (recommended for WAN/cloud access):

Set `webauthn_rp_id` in the server config to enable. The dashboard requires a
registered FIDO2 passkey (Face ID, Touch ID, Windows Hello, hardware key) to
sign in. No password is ever sent over the network — only a cryptographic proof.

Suitable for access through a [Cloudflare Tunnel](scripts/setup-cloudflare-tunnel.sh)
or any HTTPS reverse proxy. The server does not need to be directly exposed to
the internet.

**Legacy LAN-only mode** (default, no config needed):

When `webauthn_rp_id` is not set, the dashboard is accessible to any device on
your LAN (RFC 1918 address ranges and loopback). Optionally add `web_token` for
bearer-token protection.

> **Do not expose ntm-server directly to the internet without WebAuthn enabled.**
> The LAN-only filter is bypassed when requests arrive from localhost (e.g. via
> a tunnel), so always pair a tunnel with WebAuthn authentication.

### Setting up WebAuthn passkeys

1. **Choose a domain** — passkeys require an HTTPS domain. Example: `ntm.example.com`
   served through a Cloudflare Tunnel (see `scripts/setup-cloudflare-tunnel.sh`).

2. **Create an admin password file** — this bootstraps the first passkey registration:

   ```bash
   echo 'your-strong-admin-password' > /etc/ntm-server/admin-password.txt
   chmod 600 /etc/ntm-server/admin-password.txt
   ```

   > **Security note:** The plaintext password file is a temporary bootstrap mechanism.
   > On first startup with `webauthn_admin_cred_file` configured, the server
   > automatically derives a PBKDF2-HMAC-SHA256 hash, writes it to the cred file,
   > then **zeros and unlinks** the plaintext file. After migration the plaintext
   > file no longer exists.
   >
   > **Risk window:** If the server is compromised _between_ writing the plaintext
   > file and the first startup, the password could be read. Mitigate by:
   > - Creating the plaintext file immediately before starting the server.
   > - Ensuring the file has mode `600` and is owned by the server user.
   > - Deleting it manually if startup is delayed.

3. **Add to your config file** (`/etc/ntm-server/ntm-server.conf`):

   ```ini
   webauthn_rp_id             = ntm.example.com
   webauthn_rp_name           = NTM Dashboard
   webauthn_credentials_file  = /etc/ntm-server/webauthn-credentials.json
   webauthn_admin_cred_file   = /etc/ntm-server/webauthn-admin.json
   admin_password_file        = /etc/ntm-server/admin-password.txt

   # Optional: iOS App ID for passkey domain binding (requires Phase 4 iOS build)
   # webauthn_ios_app_id = TEAMID1234.com.ntm.NTMDashboard
   ```

4. **Start the server.** It will migrate the admin password automatically.

5. **Open `https://ntm.example.com/login`** in a browser and register your first
   passkey using the admin password.

6. **Sign in** with your registered passkey. Subsequent sign-ins are passwordless.

### Setting up TLS for the web dashboard

The web dashboard is **HTTPS-only**. You must provide a server certificate and
private key. The same cert/key pair is shared with the client data-ingestion
port when TLS is enabled there.

#### Option A — Self-signed certificate (typical for a private LAN)

```bash
# 1. Generate a 4096-bit RSA key and self-signed certificate.
#    Set CN to the server's LAN IP address or hostname.
openssl req -x509 -newkey rsa:4096 \
  -keyout ntm-server-key.pem \
  -out    ntm-server-cert.pem \
  -days   365 -nodes \
  -subj   "/CN=192.168.1.10"   # ← replace with your server's LAN IP or hostname

# 2. Restrict key file permissions.
chmod 600 ntm-server-key.pem

# 3. (Optional) Move to a permanent location.
sudo mkdir -p /etc/ntm-server
sudo mv ntm-server-cert.pem ntm-server-key.pem /etc/ntm-server/
sudo chmod 600 /etc/ntm-server/ntm-server-key.pem
```

Add to your config file or pass as CLI flags:

```ini
cert = /etc/ntm-server/ntm-server-cert.pem
key  = /etc/ntm-server/ntm-server-key.pem
```

**Browser trust:** Self-signed certificates are not trusted by browsers by
default. You have two options:

- **Accept the warning**: open `https://<server-ip>:8443` and click through the
  browser's "Your connection is not private" warning (safe to do on a known LAN).
- **Import as trusted CA**: add `ntm-server-cert.pem` to your browser's or OS's
  certificate store once, and future visits will show a green padlock.
  - Chrome / Chromium: Settings → Privacy → Manage certificates → Authorities → Import.
  - Firefox: Settings → Privacy → Certificates → View Certificates → Authorities → Import.
  - Linux system-wide (Arch): `sudo trust anchor --store ntm-server-cert.pem`.
  - macOS: Keychain Access → System → File → Import Items, then mark as trusted.

> **Remember to renew** the certificate before the `-days 365` expiry or the
> dashboard will show a TLS error.

#### Option B — CA-signed certificate

If you have a certificate signed by a public CA (e.g. Let's Encrypt) or an
internal CA trusted by all your devices, configure it the same way:

```ini
cert = /path/to/fullchain.pem
key  = /path/to/privkey.pem
```

Browsers will trust it automatically and no import step is required.

### Accessing the dashboard

Once `ntm-server` is running with a cert and key configured, open a browser
on any device on the same LAN and navigate to:

```
https://<server-ip>:8443
```

The page auto-refreshes every 30 seconds and shows:

- **Interfaces** table — per-client, per-interface packet and byte totals over the aggregation window.
- **Entity flows** table — top (src ASN, dst ASN) pairs sorted by bytes, showing the autonomous systems your traffic passes through.

### Bearer token (optional, not required)

A static bearer token can be configured as an extra layer of access control,
though this is **not required** in the current version:

```ini
# ntm-server.conf
web_token = your-secret-token-here
```

When set, every web request must include `Authorization: Bearer <token>` or
it receives `HTTP 401`. The `web_token` key is empty by default — the dashboard
is open to all LAN IPs without a token.

> **Note:** Full per-user authentication is a planned future enhancement.
> The bearer-token option is a stopgap for environments where a single shared
> secret is sufficient.

### Rate limiting

The server enforces a sliding-window rate limit per IP address on the web port
(default: 30 requests per minute). Excess requests receive `429 Too Many Requests`.
Configure via `web_rate_limit_rpm` (0 = unlimited).

## Authentication (Ed25519) — client data ingestion

Client and server can use **Ed25519** so that each client has a stable identity
and only allowed keys can connect to the data-ingestion port.

### Public / private key generation (OpenSSL)

**1. Generate a client private key (PEM):**

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
```

**2. Derive the public key in the format the server expects (64 hex chars = 32-byte raw key):**

```bash
openssl pkey -in client_private.pem -pubout -outform DER | tail -c 32 | xxd -p -c 0
```

Save that hex line (e.g. `a1b2c3...`) for the server's allowed list.

**3. Server allowed-keys file**

Create a text file (e.g. `allowed_clients.txt`) with one 64-character hex public
key per line. Empty lines and lines starting with `#` are ignored.

An optional **nickname** can follow the key on the same line, separated by one or
more spaces or tabs (max 64 chars, no `|` or control characters). The nickname is
shown in the web dashboard and verbose logs in place of the raw hex key — the hex
key remains the internal identifier, so renaming a client does not affect stored data.

Example `allowed_clients.txt`:

```
# <64-hex-pubkey>  [optional nickname]
a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456  kitchen-router
f0e0d0c0b0a090807060504030201000fedcba9876543210fedcba987654321  office-switch
dead0000000000000000000000000000000000000000000000000000000beef1
```

### Usage

- **Server** (require auth): `./ntm-server --allowed-keys /path/to/allowed_clients.txt [--port 5555]`
- **Client** (prove identity): `./ntm-client --identity /path/to/client_private.pem --server HOST [--port 5555]`

If the server is started **without** `--allowed-keys`, it does not perform
authentication and identifies clients by TCP peer address.

## TLS encryption (client data ingestion)

Traffic between client and server can be **encrypted with TLS** using the same
certificate configured for the web dashboard.

- **Session limit:** Each TLS session is limited to **6 hours**. After 6 hours
  the connection is closed and the client reconnects with new session keys.
- **Server:** Start with `--cert SERVER_CERT.pem` and `--key SERVER_KEY.pem`.
  Without these, the server accepts plain TCP on the ingestion port (not
  recommended for production).
- **Client:** Start with `--ca CA.pem` (CA bundle) or `--server-cert SERVER_CERT.pem`
  (certificate pinning). Without either, the client connects in plain TCP.

## Running (foreground for debugging)

```bash
cd build

# Start the server (with TLS and auth for both ports):
./ntm-server \
  --port 5555 \
  --cert ntm-server-cert.pem --key ntm-server-key.pem \
  --allowed-keys /path/to/allowed_clients.txt \
  --web-port 8443

# Start the client (with TLS and identity):
sudo ./ntm-client \
  --server 192.168.1.10 --port 5555 \
  --server-cert ntm-server-cert.pem \
  --identity /path/to/client_private.pem
```

Open `https://192.168.1.10:8443` in a browser on the same LAN to see the
live dashboard.

Without `--cert`/`--key`, traffic is plain TCP and the web dashboard is disabled.
Without `--allowed-keys` and `--identity`, the server does not require client auth.

## Running as a daemon (Unix)

```bash
cd build

# Server (with TLS; add --require-tls to refuse plain-TCP ingestion connections):
./ntm-server --daemon \
  --port 5555 \
  --cert /etc/ntm-server/ntm-server-cert.pem \
  --key  /etc/ntm-server/ntm-server-key.pem \
  --allowed-keys /etc/ntm-server/allowed_clients.txt \
  --web-port 8443

# Client (with TLS and identity):
sudo ./ntm-client --daemon \
  --server 192.168.1.10 --port 5555 \
  --server-cert /etc/ntm-server/ntm-server-cert.pem \
  --identity /path/to/client_private.pem
```

You can integrate these binaries with your init system (e.g. `systemd`) as services.

**If the client exits with status 1**, the reason is reported to stderr (foreground)
or syslog (daemon). Common causes: server not reachable, TLS or certificate
verification failure, authentication rejected (key not in server's `allowed_keys`),
or no capture-capable interfaces (run with `sudo` or appropriate capabilities).

## Server configuration (optional)

The server reads one config file via `--config FILE`. Startup options (port, TLS,
auth, web dashboard) and all limit constants can be set there; missing keys use
built-in defaults. **Command-line options override config file values.**

- **Format:** `key=value` per line; `#` starts a comment; leading/trailing space is trimmed.

See `ntm-server.conf.example` for all keys, defaults, and allowed ranges.

Key groups:

| Group | Keys |
|-------|------|
| Data ingestion | `port`, `client_bind`, `allowed_keys`, `cert`, `key`, `require_tls` |
| Web dashboard | `web_port`, `web_bind`, `web_token`, `web_rate_limit_rpm` |
| Aggregation | `aggregation_window_days` |
| IP database | `ip_db_path`, `ip_db_url`, `ip_db_update_interval_days`, `ip_db_auto_update` |
| Limits | `max_recv_buffer_bytes`, `max_flow_entries_per_key`, `max_entity_flow_entries_per_key`, `max_ifaces_per_client`, `max_entity_lines_in_summary`, `max_snapshot_entries_for_print`, `max_iface_len`, `max_ip_len`, `max_concurrent_connections`, `max_connections_per_ip`, `idle_timeout_seconds`, `max_d_lines_per_second_per_connection` |

## Client configuration

The client reads one config file via `--config FILE`. All options can be set there.

| Key | Meaning | Default |
|-----|---------|---------|
| `server` | Server host | `127.0.0.1` |
| `port` | Server port (1–65535) | `5555` |
| `identity` | Path to Ed25519 client private key PEM | (none) |
| `ca` | Path to CA bundle to verify server | (none) |
| `server_cert` | Path to server cert (pinning) | (none) |
| `send_buffer_bytes` | Fixed send buffer size (4096–2097152) | 524288 |

See `ntm-client.conf.example` in the project root.

## Security

For production deployments:

- **Use TLS on the ingestion port:** Start the server with `--cert` and `--key` and
  the client with `--ca` or `--server-cert` to protect against man-in-the-middle attacks.
  Use `--require-tls` to refuse plain-TCP ingestion connections.
- **Use Ed25519 auth:** Start the server with `--allowed-keys` and the client with
  `--identity` so only known clients can submit data.
- **Web dashboard — LAN only, no user auth (current version):** The dashboard
  hard-enforces RFC 1918 source-IP filtering and requires HTTPS, but currently
  has **no per-user authentication**. Any LAN device can view it. Do **not**
  expose port `web_port` to the internet. See the limitation notice in
  [Web Dashboard](#web-dashboard); per-user auth is planned for a future release.
- **TLS certificate renewal:** Self-signed certificates expire (default 365 days).
  Set a calendar reminder to regenerate before expiry.

> ### ⚠ Admin password stored in plain text — security limitation
>
> The optional admin data-purge feature (`admin_password_file` config key) stores the
> admin password **as plain text** in a file on disk. Protection relies **solely on Linux
> filesystem access rights** (`chmod 600` / `chown`) to prevent other users from reading
> the file. If the file is exposed — through a backup leak, a misconfigured ACL, or a
> privilege-escalation vulnerability — the password is directly visible to an attacker.
>
> **This is a known limitation of the current implementation.** Secure password storage
> (e.g. bcrypt hashing, integration with a secrets manager, or mutual-TLS client
> certificates for admin access) should be implemented in a future release before the
> admin interface is used in a high-security or multi-operator environment.
>
> See the admin interface subsection of [`SERVER_DEPLOYMENT.md`](SERVER_DEPLOYMENT.md)
> for setup instructions, hardening steps, and a full description of the limitation.

The server enforces protocol and resource limits to reduce abuse and DoS:

- **Protocol:** Maximum lengths for `D` line fields, per-connection receive buffer cap,
  and bounded caches and flow/entity maps.
- **Connections:** Global cap on concurrent connections; per-IP cap so one host cannot
  exhaust the connection pool.
- **Rate and idle:** Per-connection limit on `D` lines per second; idle timeout closes
  connections that send no data; session lifetime capped at 6 hours.
- **Web dashboard:** Per-IP sliding-window rate limit (default 30 req/min).

## Multi-LAN deployments

When multiple `ntm-client` instances run across different networks, the server uses
each client's **external (WAN) IP address** to group them into physical LANs.
Two clients that share the same external IP are considered co-located on the same
physical network; clients with different external IPs are treated as separate LANs
even if their RFC 1918 address spaces overlap.

### How LAN grouping works

On connect (and on every network change), each client:

1. Queries its external IP via a plain HTTP GET to a configurable URL
   (default: `http://checkip.amazonaws.com/`). If no LAN interface exists the check
   is skipped; if the check fails the external IP is recorded as `null`.
2. Sends an `X {ip|null}` announce line, followed by one `A ip` line per LAN
   interface address.

The server uses the external IP as a **scope** in entity keys for unidentified LAN
devices:

| Source/destination IP | Stored entity key |
|---|---|
| Client's own announced IP | 64-char hex client ID |
| Unknown device on client's LAN | `@[{externalIp}]:{lanIp}` |
| No internet reachable | `@[null]:{lanIp}` |
| Public / external IP | ASN + organisation string |

Two clients behind the **same NAT** share the same external IP, so an unknown device
seen by both generates identical keys and is merged automatically in traffic statistics.
Two clients on **different LANs** have different external IPs, so `@[1.2.3.4]:192.168.1.20`
and `@[5.6.7.8]:192.168.1.20` are kept separate even though the device IP is identical.

### Dashboard display

- **Entity Summary tab** — unknown LAN devices appear as `LAN (x.x.x.x)` where
  `x.x.x.x` is the shared external IP. If internet was unreachable they appear as
  `LAN (no internet)`. Known client IPs show the client nickname directly.
- **LAN Detail tab** — lists every unidentified LAN device with its raw IP, the
  **"Reported by"** column showing the external IP scope, and in/out byte totals.
  Devices behind the same NAT are merged into a single row regardless of how many
  clients reported them.

### Clients with no internet access

If `external_ip_url` is unreachable, the client sends `X null`. All devices seen
through clients that cannot reach the internet share the `@[null]:ip` scope in
traffic statistics and appear as `LAN (no internet)` in the dashboard.

### Dynamic network changes

`ntm-client` watches for interface changes (Linux: RTNETLINK; fallback: 30 s polling).
On any change it immediately re-announces with a fresh external IP check. The server
atomically resets the client's registry state on receipt of a new `X` line so that
stale LAN IPs from a previous network (e.g. a Wi-Fi roam or VPN connect) are never
misattributed.

## Limitations & Notes

- **Web dashboard — no per-user authentication (current version):** The web dashboard
  is accessible to any device on the LAN without a login or password. The only
  access controls are HTTPS and the hard RFC 1918 IP filter. Internet-facing
  deployment is not supported. Planned for a future version: per-user authentication
  (bearer tokens enforced, mutual-TLS client certificates, configurable CIDR allowlists).
- **Encryption on ingestion port:** Use `--cert`/`--key` on the server and `--ca` or
  `--server-cert` on the client for encrypted traffic. Sessions are limited to 6 hours.
- This is a **live monitor**; it does not persist historical data to disk.
- For very high-throughput links, a user-space monitor may still miss some packets.
- IPv4 and IPv6 are both captured on the Linux client.
