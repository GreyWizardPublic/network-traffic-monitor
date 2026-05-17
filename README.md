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

> ### ⚠ Current limitation: no per-user authentication
>
> The web dashboard currently has **no login, no password, and no bearer-token
> requirement**. Any device on your LAN that can reach the server on the web
> port (default `8443`) can view the dashboard.
>
> The only access control in place is:
> - **HTTPS** — encrypted transport, prevents passive eavesdropping.
> - **LAN-only IP filter** — connections from RFC 1918 private address ranges
>   (`10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`) and loopback only; all public
>   internet IPs are rejected at the application layer regardless of bind address.
>
> **Planned enhancement:** per-user authentication (configurable bearer tokens,
> and optionally mutual-TLS client certificates) will be added in a future release.
> Until then, treat the dashboard as LAN-visible information.
>
> **Do not expose `ntm-server` directly to the internet.** The LAN-only filter
> is not user-configurable in this version; there is no brute-force protection.
> Keep the server inside your LAN or behind a VPN.

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

The server enforces protocol and resource limits to reduce abuse and DoS:

- **Protocol:** Maximum lengths for `D` line fields, per-connection receive buffer cap,
  and bounded caches and flow/entity maps.
- **Connections:** Global cap on concurrent connections; per-IP cap so one host cannot
  exhaust the connection pool.
- **Rate and idle:** Per-connection limit on `D` lines per second; idle timeout closes
  connections that send no data; session lifetime capped at 6 hours.
- **Web dashboard:** Per-IP sliding-window rate limit (default 30 req/min).

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
