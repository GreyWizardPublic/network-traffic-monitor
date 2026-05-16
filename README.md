# Network Traffic Monitor

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

A self-hosted, multi-client network traffic aggregation system written in C++17.
See [`LICENSE`](LICENSE) for project source license (GPL-3.0-or-later) and
[`LICENSES.md`](LICENSES.md) for third-party / system / data licenses.

Headless, extensible **client–server network traffic monitor** written in **C++**.

- **Client (`ntm-client`)**: runs on devices, captures packets via `libpcap`, and sends **metadata only** to the server.
- **Server (`ntm-server`)**: runs as a headless aggregator, maintaining per-interface, per-flow, and per-country aggregates.
- **Monitoring UI (future)**: a separate process can connect to `ntm-server` to fetch aggregated data and render any GUI or dashboards you like.

Both client and server are **headless processes**. They can run either in the **foreground** (for debugging) or as **Unix daemons**.

> **Note:** Capturing packets typically requires root privileges or appropriate capabilities on your network interfaces.

## Architecture

- **ntm-client**
  - Discovers local interfaces using `pcap_findalldevs`.
  - Captures IPv4 packets on each interface.
  - For each packet, sends a single-line record to the server:
    - Format: `D iface src_ip dst_ip bytes\n`
  - No GUI; intended to be portable to other platforms (Windows, iOS, etc.) by re-implementing the capture and TCP send logic.

- **ntm-server**
  - Listens on **two TCP ports**:
    - **Client port** (default `5555`) for `ntm-client` data ingestion.
    - **Monitor port** (default `5556`) for standalone monitoring processes.
  - Optional **Ed25519 authentication**: when started with `--allowed-keys FILE`, each connecting client must prove identity with an Ed25519 key; the server uses the key’s public part as the client identifier in aggregation.
  - Consumes `D ...` data lines from clients and aggregates:
    - Per-interface totals (packets, bytes).
    - Per-flow `(src IP, dst IP)`.
    - Per-country `(src country, dst country)` resolved against a local IP→ASN/country database (no third-party library; see below).
    - Per-entity `(src entity, dst entity)` (autonomous system number + organization) resolved against the same database.
  - **Aggregation** uses a **rolling window by day** (configurable via `--config` and `aggregation_window_days`, default 7). Statistics are tracked per day; when the window is exceeded (e.g. day 8 arrives), only the **oldest day’s** data is dropped. Counters use **uint64_t**; if any counter would overflow for a client, **all statistics for that client** (all interfaces, all days in the window) are reset and the current packet is counted from zero—other clients are unaffected.
  - Exposes a simple text command for monitoring processes:
    - `IFACE_SUMMARY\n` → responds with:
      - `WINDOW_START <epoch_sec>\n` (aggregation window start time),
      - `IFACE client iface packets bytes\n` for each known interface,
      - `ENTITY\tclient\tiface\tpackets\tbytes\tsrc_entity\tdst_entity\n` for each (client, iface, src entity, dst entity) aggregate (tab-separated; entity is e.g. `AS15169 Google LLC`),
      - `END\n`
  - Prints periodic summaries to stderr in foreground mode (including the current window start).

A future monitoring process can connect to the **monitor port**, send `IFACE_SUMMARY`, and parse the reply to display aggregated data in any UI.

## Prerequisites

- A C++17-compatible compiler (e.g. `g++` or `clang++`)
- CMake 3.16+
- **OpenSSL** (libssl + libcrypto) for TLS and Ed25519 (OpenSSL 1.1.1+; on Arch: `pacman -S openssl`)
- **libcurl** for the server's auto-update of the IP database (on Arch: `pacman -S curl`)
- **zlib** for reading the gzipped IP database (on Arch: usually preinstalled; `pacman -S zlib`)
- `libpcap` and its development headers (on Arch: `pacman -S libpcap`)
- **No libmaxminddb required.** The server uses an embedded `IPRangeResolver` that consumes the **iptoasn.com** combined IPv4+IPv6 dataset (gzipped TSV, CC0 public domain). On startup the server loads the local cache file at `ip_db_path` (default `/var/lib/ntm-server/ip2asn-combined.tsv.gz`) and a background thread re-downloads it every `ip_db_update_interval_days` (default 7). The cache directory is created automatically if missing.
  - Override URL with `ip_db_url` (e.g. to mirror behind your own CDN).
  - Disable auto-update with `ip_db_auto_update=false` if you maintain the file out-of-band.
  - The download verifies HTTPS certificates (`CURLOPT_SSL_VERIFYPEER`/`HOST`) and follows up to 5 redirects, with a 30s connect timeout and 180s total timeout. A failed download leaves the existing on-disk cache intact.
- Ability to run the client with sufficient privileges for packet capture:
  - E.g. run `ntm-client` with `sudo`, or
  - Grant `CAP_NET_RAW` / `CAP_NET_ADMIN` to the binary.

## Build

From the project root:

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

This produces two binaries in `build`:

- `ntm-server`
- `ntm-client`

> For a full breakdown of every linked library and external data source, with
> SPDX identifiers and upstream URLs, see [`LICENSES.md`](LICENSES.md).

## Authentication (Ed25519)

Client and server can use **Ed25519** so that each client has a stable identity and only allowed keys can connect.

### Public / private key generation (OpenSSL)

OpenSSL is available on most systems and supports Ed25519.

**1. Generate a client private key (PEM):**

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
```

**2. Derive the public key in the format the server expects (64 hex chars = 32-byte raw key):**

```bash
# Output raw 32-byte public key as hex (one line, 64 characters)
openssl pkey -in client_private.pem -pubout -outform DER | tail -c 32 | xxd -p -c 0
```

Save that hex line (e.g. `a1b2c3...`) for the server’s allowed list. The client uses **only** the private key file (`client_private.pem`); the server uses **only** the list of public keys (hex lines).

**3. Server allowed-keys file**

Create a text file (e.g. `allowed_clients.txt`) with one 64-character hex public key per line. Empty lines and lines starting with `#` are ignored. Add the hex line from step 2 for each allowed client.

Example `allowed_clients.txt`:

```
# Client A (e.g. sensor-01)
a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
# Client B
f0e0d0c0b0a090807060504030201000fedcba9876543210fedcba987654321
```

### Usage

- **Server** (require auth): `./ntm-server --allowed-keys /path/to/allowed_clients.txt [--port 5555] [--monitor-port 5556]`
- **Client** (prove identity): `./ntm-client --identity /path/to/client_private.pem --server HOST [--port 5555]`

If the server is started **without** `--allowed-keys`, it does not perform authentication and identifies clients by TCP peer address. If the server **has** an allowed-keys file, every connection must complete Ed25519 auth; unknown or invalid keys are rejected.

## TLS encryption and session lifetime

Traffic between client and server can be **encrypted with TLS** using session-specific keys. The client verifies the server certificate, which **prevents man-in-the-middle attacks**: a MITM cannot present a valid server certificate unless it has the server’s private key.

- **Session limit:** Each TLS session is limited to **6 hours**. After 6 hours the connection is closed and the client reconnects, establishing a new session and new session keys.
- **Server:** Start with `--cert SERVER_CERT.pem` and `--key SERVER_KEY.pem` (PEM format). Without these, the server accepts plain TCP (not recommended for production).
- **Client:** Start with `--ca CA.pem` (CA bundle to verify the server cert) or `--server-cert SERVER_CERT.pem` (pin the server’s certificate). Without either, the client connects in plain TCP and does not verify the server.

For a **self-signed server certificate** (typical for a private deployment):

```bash
# Generate server key and self-signed cert (adjust -days and -subj as needed)
openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -days 365 -nodes -subj "/CN=ntm-server"
```

Use `server_cert.pem` as both the server’s `--cert` and the client’s `--server-cert` (certificate pinning). For CA-signed certs, use the CA’s bundle as the client’s `--ca`.

## Running (foreground for debugging)

In one terminal, start the server (with TLS and auth):

```bash
cd build
./ntm-server --port 5555 --monitor-port 5556 --cert server_cert.pem --key server_key.pem --allowed-keys /path/to/allowed_clients.txt
```

In another terminal on the same host, start the client with TLS and identity:

```bash
cd build
sudo ./ntm-client --server 127.0.0.1 --port 5555 --server-cert server_cert.pem --identity /path/to/client_private.pem
```

Without `--cert`/`--key` (server) and `--ca`/`--server-cert` (client), traffic is plain TCP. Without `--allowed-keys` and `--identity`, the server does not require client auth and identifies clients by IP:port.

You’ll see periodic summaries printed by `ntm-server` to stderr.

To query a summary from a standalone monitoring process, connect to the **monitor port** and send `IFACE_SUMMARY`.

Plain TCP example:

```bash
printf "IFACE_SUMMARY\n" | nc 127.0.0.1 5556
```

TLS example (when the server is started with `--cert/--key`, and especially if `--require-tls` is set):

```bash
printf "IFACE_SUMMARY\n" | openssl s_client -connect 127.0.0.1:5556 -quiet
```

The server responds with `WINDOW_START ...`, `IFACE ...` lines, optional `ENTITY\t...` lines, and then `END`.

If you configured **monitor authentication** (`monitor_allowed_keys` / `--monitor-allowed-keys`), use the included `ntm-monitor` example client (it supports TLS verification/pinning and Ed25519 auth v2):

```bash
cd build
./ntm-monitor --server 127.0.0.1 --monitor-port 5556 --server-cert server_cert.pem --identity /path/to/monitor_private.pem
```

## Running as a daemon (Unix)

- **Server** (with TLS; add `--require-tls` when exposed to the internet):

  ```bash
  cd build
  ./ntm-server --daemon --port 5555 --monitor-port 5556 --cert server_cert.pem --key server_key.pem --allowed-keys /path/to/allowed_clients.txt
  ```

- **Client** (with TLS and identity):

  ```bash
  cd build
  sudo ./ntm-client --daemon --server 127.0.0.1 --port 5555 --server-cert server_cert.pem --identity /path/to/client_private.pem
  ```

You can integrate these binaries with your init system (e.g. `systemd`) as services.

**If the client exits with status 1** (e.g. when run as a systemd unit), the reason is now reported: when run in the foreground you’ll see it on stderr; when run with `--daemon`, it is logged to syslog (e.g. `journalctl -u ntm-client` or `journalctl -t ntm-client`). Common causes: server not reachable, TLS or server-cert verification failure, authentication rejected (client key not in server’s `allowed_keys`), or no capture-capable interfaces (run with `sudo` or appropriate capabilities).

## Server configuration (optional)

The server reads one config file via `--config FILE`. Startup options (port, TLS, auth) and all boundary/limit constants can be set there; missing keys use built-in defaults. **Command-line options override config file values** when both are present.

- **Format:** `key=value` per line; `#` starts a comment; leading/trailing space is trimmed.
- **Startup / TLS / auth (config or CLI):** `port` (1–65535), `monitor_port` (1–65535), `allowed_keys` (path to allowed Ed25519 public keys), `cert` (TLS server cert PEM path), `key` (TLS server key PEM path), `require_tls` (true/yes/1 or false/no/0).
- **Monitor hardening (config or CLI):** `monitor_bind` (IPv4 bind address; default `127.0.0.1` local-only), `monitor_allowed_keys` (allowed Ed25519 public keys for monitoring), `require_tls_monitor` (true/yes/1), plus monitor limits `max_monitor_summaries_per_second_per_connection`, `max_iface_lines_in_summary`, `max_summary_bytes`.
- **Limit keys:** `aggregation_window_days`, `max_recv_buffer_bytes`, `max_flow_entries_per_key`, `max_entity_flow_entries_per_key`, `max_ifaces_per_client`, `max_entity_lines_in_summary`, `max_snapshot_entries_for_print`, `max_iface_len`, `max_ip_len`, `max_concurrent_connections`, `max_connections_per_ip`, `max_concurrent_monitor_connections`, `max_monitor_connections_per_ip`, `idle_timeout_seconds`, `max_d_lines_per_second_per_connection`.
- **IP database keys:** `ip_db_path`, `ip_db_url`, `ip_db_update_interval_days`, `ip_db_auto_update`.
- Statistics are stored **per day**. When more than `aggregation_window_days` days exist, only the **oldest day** is dropped (no full reset).

Example: `./ntm-server --config /path/to/ntm-server.conf ...`. See `ntm-server.conf.example` for all keys, defaults, and allowed ranges.

## Client configuration (one file)

The client reads **at most one config file** via `--config FILE`. All options can be set there; command-line arguments override config file values.

- **Format:** `key=value` per line; `#` starts a comment; leading/trailing space is trimmed.
- **Keys:** `server`, `port`, `identity`, `ca`, `server_cert`, `send_buffer_bytes`. Omitted keys use defaults.

| Key | Meaning | Default |
|-----|---------|---------|
| `server` | Server host | `127.0.0.1` |
| `port` | Server port (1–65535) | `5555` |
| `identity` | Path to Ed25519 client private key PEM | (none) |
| `ca` | Path to CA bundle to verify server | (none) |
| `server_cert` | Path to server cert (pinning) | (none) |
| `send_buffer_bytes` | Fixed send buffer size (4096–2097152) | 524288 |

Example: `./ntm-client --config /path/to/ntm-client.conf` or override: `./ntm-client --config ntm-client.conf --server 192.168.1.1`

See `ntm-client.conf.example` in the project root.

## Security

For production deployments, especially when the server is exposed to the internet:

- **Use TLS:** Start the server with `--cert` and `--key` so all traffic is encrypted. Start the client with `--ca` or `--server-cert` so it verifies the server and is protected against man-in-the-middle attacks. Without TLS, all traffic (including authentication) is cleartext.
- **Require TLS (internet exposure):** Use `--require-tls` so the server refuses to start unless `--cert` and `--key` are set; use this when the server is reachable from the internet to avoid accidental plain-TCP exposure.
- **Use authentication:** Start the server with `--allowed-keys` and the client with `--identity` so only known clients can connect. Without `--allowed-keys`, the server identifies clients by TCP peer address only and accepts any connection.

The server enforces protocol and resource limits to reduce abuse and DoS:

- **Protocol:** Maximum lengths for `D` line fields (iface, src_ip, dst_ip), per-connection receive buffer cap, and bounded caches and flow/entity maps (see memory assessment).
- **Connections:** Global cap on concurrent connections; per-IP cap so one host cannot exhaust the connection pool. When a limit is hit, new connections are closed and a short message is logged to stderr.
- **Rate and idle:** Per-connection limit on `D` lines per second (excess lines dropped); idle timeout closes connections that send no data for a configured period. Session lifetime is capped (e.g. 6 hours).

Detailed security and vulnerability assessments are in the `docs/` folder:

- **Server and protocol:** `docs/SERVER_AND_PROTOCOL_SECURITY_ASSESSMENT.md` — transport, authentication, protocol parsing, and server-side DoS mitigations.
- **Server memory:** `docs/SERVER_MEMORY_ASSESSMENT.md` — bounded memory use for caches, flow maps, and buffers.
- **Client:** `docs/CLIENT_SECURITY_ASSESSMENT.md` — client-side overflow and config safety.

## Limitations & Notes

- **Encryption:** Use `--cert`/`--key` on the server and `--ca` or `--server-cert` on the client for encrypted traffic and protection against MITM. Sessions are limited to 6 hours, then renegotiated.
- This is a **live monitor**; it does not persist historical data to disk.
- For very high-throughput links, a user-space monitor may still miss some packets; for production-grade monitoring you may want a dedicated C/Go-based collector or kernel-level capture.
- IPv4 and IPv6 are both captured when using the Linux client.

