# ntm-server Deployment Guide

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build](#2-build)
3. [Directory layout](#3-directory-layout)
4. [TLS certificate](#4-tls-certificate)
5. [Ed25519 client keys](#5-ed25519-client-keys)
6. [Configuration file](#6-configuration-file)
7. [First run (foreground)](#7-first-run-foreground)
8. [Running as a daemon](#8-running-as-a-daemon)
9. [systemd service unit](#9-systemd-service-unit)
10. [IP → ASN database](#10-ip--asn-database)
11. [Web dashboard access](#11-web-dashboard-access)
12. [Resource limits reference](#12-resource-limits-reference)
13. [Security hardening checklist](#13-security-hardening-checklist)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Prerequisites

| Package | Arch Linux | Debian / Ubuntu |
|---------|-----------|-----------------|
| C++17 compiler | `gcc` or `clang` | `build-essential` |
| CMake ≥ 3.16 | `cmake` | `cmake` |
| OpenSSL ≥ 1.1.1 | `openssl` | `libssl-dev` |
| libcurl | `curl` | `libcurl4-openssl-dev` |
| zlib | `zlib` | `zlib1g-dev` |
| libpcap (client only) | `libpcap` | `libpcap-dev` |

**cpp-httplib** is vendored at `src/httplib.h` — no separate install needed.

---

## 2. Build

```bash
git clone <repo-url>
cd network-traffic-monitor
mkdir -p build && cd build
cmake ..
cmake --build .
```

Produces `build/ntm-server` and `build/ntm-client`.

---

## 3. Directory layout

A minimal production layout:

```
/usr/local/bin/ntm-server          # binary
/etc/ntm-server/
    ntm-server.conf                # config file
    server_cert.pem                # TLS certificate
    server_key.pem                 # TLS private key (chmod 600)
    allowed_clients.txt            # Ed25519 public keys (one per line)
/var/lib/ntm-server/
    ip2asn-combined.tsv.gz         # IP→ASN cache (auto-downloaded on first start)
```

```bash
sudo install -m 755 build/ntm-server /usr/local/bin/ntm-server
sudo mkdir -p /etc/ntm-server /var/lib/ntm-server
```

---

## 4. TLS certificate

The **same cert/key pair** is used for both the client data-ingestion port and the HTTPS web
dashboard. Without them, the web dashboard is disabled and ingestion runs over plain TCP.

### Option A — Self-signed (typical LAN deployment)

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout server_key.pem \
  -out    server_cert.pem \
  -days   365 -nodes \
  -subj   "/CN=192.168.1.10"    # replace with your server's LAN IP or hostname

sudo mv server_cert.pem server_key.pem /etc/ntm-server/
sudo chmod 600 /etc/ntm-server/server_key.pem
```

Set a calendar reminder to regenerate before the `-days` value expires, or the dashboard will
show a TLS error.

### Option B — CA-signed (Let's Encrypt or internal CA)

```ini
cert = /etc/letsencrypt/live/yourhost/fullchain.pem
key  = /etc/letsencrypt/live/yourhost/privkey.pem
```

No browser import step required when using a public CA.

### Trusting a self-signed cert in browsers

| Browser / OS | Steps |
|---|---|
| Chrome / Chromium | Settings → Privacy → Manage Certificates → Authorities → Import |
| Firefox | Settings → Privacy → Certificates → View Certificates → Authorities → Import |
| Arch (system-wide) | `sudo trust anchor --store /etc/ntm-server/server_cert.pem` |
| macOS | Keychain Access → System → File → Import Items → mark as Always Trust |

---

## 5. Ed25519 client keys

When `allowed_keys` is configured, only clients that sign the handshake with a listed key can
connect. Without it, the server identifies clients by TCP peer address (no authentication).

### Generate a keypair (run on each client machine)

```bash
# 1. Private key (keep this on the client only)
openssl genpkey -algorithm ED25519 -out client_private.pem

# 2. Derive the 64-char hex public key to add to the server's allowlist
openssl pkey -in client_private.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 0
```

### Server allowlist file

Create `/etc/ntm-server/allowed_clients.txt`:

```
# sensor-01 (kitchen router)
a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

# sensor-02 (office switch)
f0e0d0c0b0a090807060504030201000fedcba9876543210fedcba987654321
```

- One 64-character hex key per line.
- Lines starting with `#` and blank lines are ignored.
- Malformed entries are logged as warnings at startup so keys are never silently lost.
- Membership checks use **constant-time comparison** (`CRYPTO_memcmp`) to prevent timing
  side-channels.

---

## 6. Configuration file

Copy and edit the example:

```bash
sudo cp ntm-server.conf.example /etc/ntm-server/ntm-server.conf
```

Minimal production config (all other keys use built-in defaults):

```ini
# /etc/ntm-server/ntm-server.conf

# ── Data ingestion ────────────────────────────────────────────────────────────
# cert, key, and allowed_keys are all mandatory — the server refuses to start without them.
port            = 5555
cert            = /etc/ntm-server/server_cert.pem
key             = /etc/ntm-server/server_key.pem
allowed_keys    = /etc/ntm-server/allowed_clients.txt

# ── Web dashboard ─────────────────────────────────────────────────────────────
web_port        = 8443
web_token       = change-me-to-a-strong-secret

# ── Aggregation ───────────────────────────────────────────────────────────────
aggregation_window_days = 7

# ── IP database ───────────────────────────────────────────────────────────────
ip_db_path                 = /var/lib/ntm-server/ip2asn-combined.tsv.gz
ip_db_auto_update          = true
ip_db_update_interval_days = 7
```

**Key precedence:** command-line flags override config file values, which override built-in
defaults.

---

## 7. First run (foreground)

Run in the foreground first to verify everything is working before daemonising:

```bash
sudo ntm-server \
  --config /etc/ntm-server/ntm-server.conf \
  --verbose
```

Expected startup output on stderr:
- Confirmation that the TLS cert/key loaded successfully.
- Number of allowed keys loaded (if `allowed_keys` is set).
- IP database loaded, or a download triggered if the cache file is missing.
- Listening ports for ingestion and the web dashboard.

Open `https://<server-ip>:8443` in a browser on the same LAN to confirm the dashboard loads,
then press `Ctrl+C` to stop. If no errors appear, proceed to daemon mode.

---

## 8. Running as a daemon

```bash
sudo ntm-server \
  --daemon \
  --config /etc/ntm-server/ntm-server.conf
```

In daemon mode:
- The process double-forks and detaches from the terminal.
- All log output goes to **syslog** (`LOG_DAEMON` facility).
- stderr/stdout are redirected to `/dev/null`.

View logs:

```bash
journalctl -t ntm-server -f        # systemd systems
sudo tail -f /var/log/daemon.log    # traditional syslog
```

---

## 9. systemd service unit

An annotated example unit file is provided at `ntm-server.service.example` in the project
root. Copy and adapt it:

```bash
sudo cp ntm-server.service.example /etc/systemd/system/ntm-server.service
```

The example below documents the key options. Two common hardening options —
`MemoryDenyWriteExecute` and `PrivateUsers` — are explicitly **not** enabled because both
silently break HTTPS: OpenSSL's TLS implementation uses `mprotect()` internally for
hardware-accelerated ciphers (AES-NI etc.), which `MemoryDenyWriteExecute` blocks with
`EPERM`, causing the SSL context to fail initialisation and the web dashboard to be disabled
while the ingestion port continues running. `PrivateUsers` causes the same failure via user
namespace interference with OpenSSL socket operations. `RestrictAddressFamilies` is used
instead to provide equivalent attack-surface reduction without breaking TLS.

Full contents of `/etc/systemd/system/ntm-server.service`:

```ini
[Unit]
Description=NTM network traffic aggregation server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/ntm-server \
    --daemon \
    --config /etc/ntm-server/ntm-server.conf
Restart=on-failure
RestartSec=5s

# Lock down the service
User=ntm-server
Group=ntm-server
RuntimeDirectory=ntm-server
StateDirectory=ntm-server
LogsDirectory=ntm-server
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ntm-server /etc/ntm-server
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Create a dedicated user and enable the service:

```bash
sudo useradd -r -s /sbin/nologin -d /var/lib/ntm-server ntm-server
sudo chown -R ntm-server:ntm-server /var/lib/ntm-server /etc/ntm-server
sudo chmod 640 /etc/ntm-server/server_key.pem

sudo systemctl daemon-reload
sudo systemctl enable --now ntm-server
sudo systemctl status ntm-server
```

---

## 10. IP → ASN database

The server uses **iptoasn.com's** CC0-licensed `ip2asn-combined.tsv.gz` for IP → country and
ASN resolution. No MaxMind account or `libmaxminddb` is required.

- **First start:** if the file at `ip_db_path` is missing, the server downloads it automatically
  at startup (requires outbound HTTPS to `iptoasn.com`).
- **Auto-update:** a background thread re-downloads the file every `ip_db_update_interval_days`
  (default 7). Set `ip_db_auto_update=false` to disable.
- **Air-gapped servers:** pre-download the file on another machine and place it at `ip_db_path`
  before first start:

```bash
curl -o /var/lib/ntm-server/ip2asn-combined.tsv.gz \
  https://iptoasn.com/data/ip2asn-combined.tsv.gz
```

If the database is unavailable, IP lookups return empty country/entity strings but traffic
aggregation continues normally.

---

## 11. Web dashboard access

Navigate to `https://<server-ip>:8443` from any device on the LAN.

The page auto-refreshes every 30 seconds and shows:

- **Interfaces** — per-client, per-interface packet and byte totals over the aggregation window.
- **Entity flows** — top (src ASN, dst ASN) pairs sorted by bytes.

### Access controls in the current version

| Control | Status |
|---|---|
| HTTPS (TLS) | Always enforced when cert/key are configured |
| RFC 1918 LAN-only IP filter | Always enforced (hard-coded, not configurable) |
| Bearer token (`web_token`) | Optional; strongly recommended |
| Per-user login / password | Not yet implemented (planned) |
| Rate limiting | 30 req/min per IP (configurable via `web_rate_limit_rpm`) |

When `web_token` is set, every request must include:

```
Authorization: Bearer <your-token>
```

> **Do not expose `web_port` to the internet.** The LAN filter is the only perimeter and there
> is no brute-force protection on the token.

---

## 12. Resource limits reference

All limits are settable in the config file. Values outside the allowed range are rejected at
startup with an error message.

| Key | Default | Range | Purpose |
|---|---|---|---|
| `max_concurrent_connections` | 1000 | 10–100000 | Global concurrent client connections |
| `max_connections_per_ip` | 20 | 1–1000 | Per-IP concurrent connections |
| `idle_timeout_seconds` | 300 | 10–86400 | Close connections that send no data |
| `max_d_lines_per_second_per_connection` | 20000 | 100–1000000 | Per-connection data rate cap; excess lines are dropped |
| `max_recv_buffer_bytes` | 1048576 | 4096–16M | Per-connection receive buffer cap; connection closed if exceeded |
| `max_flow_entries_per_key` | 100000 | 100–1000000 | Per-(client\|iface) per-day IP flow entries; evicts smallest-by-bytes entry when full |
| `max_entity_flow_entries_per_key` | 100000 | 100–1000000 | Same, for ASN entity flows |
| `max_ifaces_per_client` | 256 | 1–100000 | Per-client interface name cardinality cap |
| `max_entity_lines_in_summary` | 50000 | 100–1000000 | Rows returned by the dashboard's `/api/summary` endpoint |
| `max_iface_len` | 64 | 8–256 | Maximum length of the interface name field in `D` lines |
| `max_ip_len` | 50 | 15–64 | Maximum length of IP address fields in `D` lines |

**Overflow protection:** if any `uint64_t` counter for a client would overflow, all statistics
for that client are silently reset. Other clients are unaffected.

**Session lifetime:** each TLS session is capped at 6 hours. After that the connection is
closed and the client reconnects with fresh session keys.

---

## 13. Security hardening checklist

- [ ] TLS configured: `cert` and `key` set (mandatory — server refuses to start without them)
- [ ] Ed25519 auth configured: `allowed_keys` set (mandatory — server refuses to start without it)
- [ ] Each client started with `--identity` matching a key in `allowed_clients.txt`
- [ ] `web_token` set to a strong random secret
- [ ] Server binary runs as a dedicated unprivileged user (`ntm-server`)
- [ ] `server_key.pem` permissions are `640` (owner `ntm-server`, group `ntm-server`)
- [ ] `web_port` blocked at the firewall from reaching the internet
- [ ] `port` (ingestion) blocked at the firewall unless remote clients are used
- [ ] TLS certificate expiry reminder set (self-signed default is 365 days)
- [ ] `ip_db_auto_update=true` or a cron job in place to refresh the ASN database
- [ ] systemd hardening options applied (`PrivateTmp`, `ProtectSystem`, `NoNewPrivileges`)

---

## 14. Troubleshooting

**Server refuses to start**
- `cert` and `key` are mandatory — the server exits with an error if either is missing.
- `allowed_keys` is mandatory — the server exits with an error if not set or the file contains
  no valid keys. Check the path and file contents.

**Web dashboard does not load**
- Confirm `cert` and `key` are correctly set and the files are readable by the service user.
- Use `https://` not `http://` in the browser address bar.
- For self-signed certs, import or accept the certificate in the browser first.

**`allowed_keys` set but 0 keys loaded at startup**
- Check the file path and that the server process can read it.
- Each key must be exactly 64 hex characters on its own line with no trailing whitespace.
- Malformed entries are logged as warnings at startup — check syslog or journal output.

**Clients connect but no traffic appears in the dashboard**
- Run the server with `--verbose` in the foreground to see per-connection events.
- Confirm the client is targeting the correct `--server` and `--port`.
- If `require_tls=true`, clients must be started with `--ca` or `--server-cert`.

**IP database fails to download on first start**
- Manually download the file and place it at `ip_db_path` (see [Section 10](#10-ip--asn-database)).
- Aggregation continues without the database; only country/ASN resolution is affected.

**`max_ifaces_per_client` rejection warnings in logs**
- A client is submitting `D` lines with more distinct interface names than the cap allows.
- Either raise `max_ifaces_per_client` in config, or investigate whether the client is
  generating spurious interface names.
- The per-client interface count persists across day-bucket rollovers; it is only reset when
  a client's stats are cleared due to counter overflow.

**Port already in use**
- Another process is bound to `port` (5555) or `web_port` (8443).
- Run `sudo ss -tlnp | grep 5555` to identify it, then either stop it or change the port in
  config.
