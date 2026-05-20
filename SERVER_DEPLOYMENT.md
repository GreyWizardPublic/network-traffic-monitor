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
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release .
cmake --build build-linux -j$(nproc)
```

Produces `build-linux/ntm-server` and `build-linux/ntm-client`.

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
    webauthn-admin.json            # WebAuthn: PBKDF2 admin credential (WebAuthn mode only)
    webauthn-credentials.json      # WebAuthn: registered passkeys   (WebAuthn mode only)
/var/lib/ntm-server/
    ip2asn-combined.tsv.gz         # IP→ASN cache (auto-downloaded on first start)
```

```bash
sudo install -m 755 build-linux/ntm-server /usr/local/bin/ntm-server
sudo mkdir -p /etc/ntm-server /var/lib/ntm-server
```

---

## 4. TLS certificate

The **same cert/key pair** is used for both the client data-ingestion port and the HTTPS web
dashboard. **TLS is mandatory** — the server refuses to start without a valid cert/key pair.

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

`allowed_keys` is mandatory — the server refuses to start without it. Every connecting client
must sign the handshake with an Ed25519 private key whose public key is listed in the file.
Connections from clients not on the list are rejected after the TLS handshake completes.

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
# Format: <64-hex-pubkey>  [optional nickname]
#
# The nickname is shown in the web dashboard and server logs instead of the raw
# 64-character hex key.  It must be on the same line, separated from the key by
# one or more spaces or tabs.  Maximum 64 characters; must not contain '|' or
# ASCII control characters.
#
# Lines starting with '#' and blank lines are ignored.

a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456  kitchen-router
f0e0d0c0b0a090807060504030201000fedcba9876543210fedcba987654321  office-switch
dead0000000000000000000000000000000000000000000000000000000beef1
```

- One 64-character hex public key per line.
- An optional **nickname** follows the key, separated by whitespace; it replaces the
  raw hex in the web dashboard and verbose logs (the hex key remains the internal
  identifier in all stored data, so renaming a client never affects historical records).
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

### Minimal config — WebAuthn mode (recommended)

```ini
# /etc/ntm-server/ntm-server.conf

# ── Data ingestion ────────────────────────────────────────────────────────────
# cert, key, and allowed_keys are mandatory — the server refuses to start without them.
port            = 5555
cert            = /etc/ntm-server/server_cert.pem
key             = /etc/ntm-server/server_key.pem
allowed_keys    = /etc/ntm-server/allowed_clients.txt
client_bind     = 192.168.1.x    # restrict ingestion to LAN interface

# ── Web dashboard ─────────────────────────────────────────────────────────────
web_port        = 8443
web_bind        = 127.0.0.1      # Cloudflare Tunnel connects from localhost

# ── WebAuthn passkey authentication ──────────────────────────────────────────
webauthn_rp_id             = ntm.example.com
webauthn_rp_name           = NTM Dashboard
webauthn_credentials_file  = /etc/ntm-server/webauthn-credentials.json
webauthn_admin_cred_file   = /etc/ntm-server/webauthn-admin.json
admin_password_file        = /etc/ntm-server/admin-password.txt   # erased after first start

# ── Aggregation ───────────────────────────────────────────────────────────────
aggregation_window_days = 7

# ── IP database ───────────────────────────────────────────────────────────────
ip_db_path                 = /var/lib/ntm-server/ip2asn-combined.tsv.gz
ip_db_auto_update          = true
ip_db_update_interval_days = 7
```

### Minimal config — legacy LAN mode

```ini
# /etc/ntm-server/ntm-server.conf

port            = 5555
cert            = /etc/ntm-server/server_cert.pem
key             = /etc/ntm-server/server_key.pem
allowed_keys    = /etc/ntm-server/allowed_clients.txt

web_port        = 8443
web_token       = change-me-to-a-strong-secret   # optional but recommended

aggregation_window_days = 7
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
- Number of allowed Ed25519 keys loaded.
- IP database loaded, or a download triggered if the cache file is missing.
- In WebAuthn mode: `admin password migrated to PBKDF2 and plaintext file erased` (first run only).
- Listening ports for ingestion and the web dashboard.

If `cert`, `key`, or `allowed_keys` are missing the server exits immediately with an error
before opening any port.

**Accessing the dashboard after first run:**

- **WebAuthn mode:** open `https://ntm.example.com` (your tunnel domain). The server is
  bound to `127.0.0.1`, so `https://<server-ip>:8443` will not work.
- **Legacy LAN mode:** open `https://<server-ip>:8443` from any device on the same LAN.

Press `Ctrl+C` to stop. If no errors appear, proceed to daemon mode.

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

Full contents of `ntm-server.service.example`:

```ini
[Unit]
Description=Network Monitor Server Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/ntm-server \
    --daemon \
    --config /etc/ntm-server/ntm-server.conf
Restart=on-failure
RestartSec=5s

User=ntm-server
Group=ntm-server
WorkingDirectory=/var/lib/ntm-server
RuntimeDirectory=ntm-server
StateDirectory=ntm-server
LogsDirectory=ntm-server

# Allow the server to read its config and write WebAuthn credential files.
ReadWritePaths=/var/lib/ntm-server /etc/ntm-server

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
PrivateDevices=true
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6

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

### WebAuthn mode

Open `https://ntm.example.com` (your Cloudflare Tunnel or reverse-proxy domain) from any
device. The server redirects unauthenticated visits to `/login` automatically.

Since the server is bound to `127.0.0.1`, it is **not** reachable directly via
`https://<server-ip>:8443` — all access goes through the tunnel.

### Legacy LAN mode

Navigate to `https://<server-ip>:8443` from any device on the LAN.

The page auto-refreshes every 30 seconds and shows:

- **Interfaces** — per-client, per-interface packet and byte totals over the aggregation window.
- **Entity flows** — top (src ASN, dst ASN) pairs sorted by bytes.

### Access controls summary

| Control | WebAuthn mode | Legacy mode |
|---|---|---|
| HTTPS (TLS) | Always enforced (mandatory) | Always enforced (mandatory) |
| RFC 1918 LAN-only IP filter | **Bypassed** — authentication handled by passkey session | Always enforced |
| Passkey session | Required for all protected endpoints | Not available |
| Bearer token (`web_token`) | Not used (superseded by passkey sessions) | Optional; recommended |
| Rate limiting | 30 req/min per IP (configurable via `web_rate_limit_rpm`) | Same |

### Admin data purge

An admin page at `https://<host>/admin` lets an operator permanently purge all historical
traffic data for a selected client.

**WebAuthn mode:** no password entry required — the existing passkey session is sufficient.
Navigate to `/admin` after signing in.

**Legacy mode:** the feature is disabled (returns 404) unless `admin_password_file` is
configured. To set up:

```bash
# Write a strong password into the file (no quotes, no newline issues)
echo "your-strong-admin-password" | sudo tee /etc/ntm-server/admin_password > /dev/null
sudo chown ntm-server:ntm-server /etc/ntm-server/admin_password
sudo chmod 600 /etc/ntm-server/admin_password
```

Add to the config file:

```ini
admin_password_file = /etc/ntm-server/admin_password
```

The server reads the first line of the file at startup and stores it in memory.
The admin password is **stored as plain text** in the file and protected solely by
filesystem permissions (`chmod 600`). In WebAuthn mode, set up `admin_password_file`
only temporarily to bootstrap — it is migrated to PBKDF2 and the plaintext erased on
first start.

**Rate limiting:** the `/api/admin/purge` endpoint has a stricter rate limit of
5 requests per minute per IP.

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
- [ ] `web_bind` set to `127.0.0.1` (Cloudflare Tunnel / WebAuthn deployment) or the server's LAN IP — do **not** leave as `0.0.0.0` in WebAuthn mode; the LAN-only source-IP filter is bypassed when WebAuthn is active
- [ ] `web_port` additionally blocked at the firewall from reaching the internet
- [ ] `client_bind` set to the server's LAN IP (or `127.0.0.1` if all clients are local) rather than `0.0.0.0`
- [ ] `port` (ingestion) additionally blocked at the firewall unless remote clients are used
- [ ] **WebAuthn mode:** `webauthn_rp_id`, `webauthn_credentials_file`, and `webauthn_admin_cred_file` all set
- [ ] **WebAuthn mode:** `webauthn-admin.json` and `webauthn-credentials.json` owned by service account with `chmod 600`
- [ ] **WebAuthn mode:** admin password migration confirmed in `journalctl` on first start (`admin password migrated to PBKDF2 and plaintext file erased`)
- [ ] **Legacy mode:** `web_token` set to a strong random secret
- [ ] **Legacy mode:** if admin interface enabled, `admin_password` file is `chmod 600`, owned by service account
- [ ] **Legacy mode:** admin password file excluded from backups or backup ACLs restricted (plain-text storage)
- [ ] `server_key.pem` permissions are `640` (owner `ntm-server`, group `ntm-server`)
- [ ] TLS certificate expiry reminder set (self-signed default is 365 days)
- [ ] `ip_db_auto_update=true` or a cron job in place to refresh the ASN database
- [ ] systemd hardening options applied (`PrivateTmp`, `ProtectSystem`, `NoNewPrivileges`, `RestrictAddressFamilies`)

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
- In WebAuthn mode, use the tunnel domain URL (`https://ntm.example.com`), not the server IP
  directly — the server is bound to `127.0.0.1` and is not reachable on the LAN interface.

**`allowed_keys` set but 0 keys loaded at startup**
- Check the file path and that the server process can read it.
- Each key must be exactly 64 hex characters on its own line with no trailing whitespace.
- Malformed entries are logged as warnings at startup — check syslog or journal output.

**Clients connect but no traffic appears in the dashboard**
- Run the server with `--verbose` in the foreground to see per-connection events.
- Confirm the client is targeting the correct `--server` and `--port`.
- The server always requires TLS — clients must be started with `--ca` or `--server-cert`.
- The server always requires Ed25519 auth — clients must be started with `--identity` and
  their public key must be present in `allowed_clients.txt`.

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

**WebAuthn: "admin credentials not configured" on the login page**

The server could not read or create the admin credential file. Three distinct
failure modes exist — all are non-fatal (the server keeps running) but leave
WebAuthn registration disabled:

| Symptom | Root cause | Fix |
|---|---|---|
| `"admin credentials not configured"` at register time | `webauthn_admin_cred_file` is missing from config, the file itself is absent, or unreadable | See steps below |
| Registration appears to succeed but passkeys are gone after a restart | `webauthn_credentials_file` is unwritable — credentials are kept in memory but cannot be persisted | Fix file permissions (see below); after fixing, re-register |
| `journalctl` shows `"admin password migration failed"` | `admin_password_file` is readable but `webauthn_admin_cred_file` target path is unwritable | Fix write permission on the target directory/file |

**Diagnosing with journalctl:**

```bash
journalctl -u ntm-server --since "10 minutes ago" | grep -i "webauthn\|admin\|migrat\|credentials"
```

Key log messages to look for:

| Log message | Meaning |
|---|---|
| `admin password migrated to PBKDF2 and plaintext file erased` | Migration succeeded — normal first-run output |
| `admin password migration failed: cannot write <path>` | `webauthn_admin_cred_file` is not writable |
| `ntm WebAuthn: cannot write credentials file '<path>'` | `webauthn_credentials_file` is not writable — passkeys will be lost on restart |
| `failed to read admin password file` (Warn) | `admin_password_file` is missing or unreadable |

**Setting up correct file ownership and permissions:**

The server process runs as the `ntm-server` user (or whichever user `User=` is set to
in the systemd unit). All WebAuthn files must be owned by that user:

```bash
# Replace ntm-server with your service user if different
sudo chown ntm-server:ntm-server /etc/ntm-server/webauthn-admin.json
sudo chown ntm-server:ntm-server /etc/ntm-server/webauthn-credentials.json
sudo chmod 600 /etc/ntm-server/webauthn-admin.json
sudo chmod 600 /etc/ntm-server/webauthn-credentials.json

# If the files do not exist yet, create empty placeholders first:
sudo -u ntm-server touch /etc/ntm-server/webauthn-admin.json \
                         /etc/ntm-server/webauthn-credentials.json
sudo chmod 600 /etc/ntm-server/webauthn-admin.json \
               /etc/ntm-server/webauthn-credentials.json
```

The directory itself must also be writable by the service user if the files do
not yet exist:

```bash
sudo chown ntm-server:ntm-server /etc/ntm-server
sudo chmod 750 /etc/ntm-server
```

After correcting permissions, restart the server:

```bash
sudo systemctl restart ntm-server
journalctl -fu ntm-server   # watch for the migration success message
```

**Important:** The server **does not exit** when it cannot read or write these
files — it continues running in a degraded state where passkey registration is
disabled. This is intentional so that an existing authenticated session can
still access the dashboard. Always confirm via `journalctl` that migration
succeeded on first run before attempting passkey registration.
