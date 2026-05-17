# ntm-client Deployment Guide

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build](#2-build)
3. [Directory layout](#3-directory-layout)
4. [Packet capture privileges](#4-packet-capture-privileges)
5. [Ed25519 identity key](#5-ed25519-identity-key)
6. [TLS server verification](#6-tls-server-verification)
7. [Configuration file](#7-configuration-file)
8. [First run (foreground)](#8-first-run-foreground)
9. [Running as a daemon](#9-running-as-a-daemon)
10. [systemd service unit](#10-systemd-service-unit)
11. [Behaviour reference](#11-behaviour-reference)
12. [Security hardening checklist](#12-security-hardening-checklist)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Prerequisites

| Package | Arch Linux | Debian / Ubuntu |
|---------|-----------|-----------------|
| C++17 compiler | `gcc` or `clang` | `build-essential` |
| CMake ≥ 3.16 | `cmake` | `cmake` |
| OpenSSL ≥ 1.1.1 | `openssl` | `libssl-dev` |
| libpcap | `libpcap` | `libpcap-dev` |

The client does **not** require libcurl, zlib, or cpp-httplib.

---

## 2. Build

```bash
git clone <repo-url>
cd network-traffic-monitor
mkdir -p build && cd build
cmake ..
cmake --build .
```

Produces `build/ntm-client` (and `build/ntm-server`).

---

## 3. Directory layout

A minimal production layout:

```
/usr/local/bin/ntm-client          # binary
/etc/ntmclient/
    ntm-client.conf                # config file
    client_private.pem             # Ed25519 private key (chmod 600) — mandatory
    server_cert.pem                # server certificate for TLS verification — mandatory
```

```bash
sudo install -m 755 build/ntm-client /usr/local/bin/ntm-client
sudo mkdir -p /etc/ntmclient
```

---

## 4. Packet capture privileges

`ntm-client` captures packets via **libpcap** in promiscuous mode. Libpcap requires either:

- **Root** (`sudo`), or
- **`CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities** granted to the process.

### Option A — Run as root (simplest, not recommended for production)

```bash
sudo ntm-client --server 192.168.1.10
```

### Option B — Capabilities on the binary (setcap)

This allows the binary to capture without running as root:

```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/ntm-client
```

Verify:

```bash
getcap /usr/local/bin/ntm-client
# expected: /usr/local/bin/ntm-client cap_net_admin,cap_net_raw=eip
```

> **Note:** `setcap` grants capabilities permanently to the binary. Any user can then run
> `ntm-client` with those capabilities. Use a dedicated system user and the systemd service
> unit (Section 10) to scope access.

### Option C — systemd `AmbientCapabilities` (recommended for daemon mode)

Grant capabilities only to the service process at runtime without modifying the binary. This
is the approach used in `ntm-client.service.example` — see Section 10.

---

## 5. Ed25519 identity key

An Ed25519 identity key is **mandatory**. The server always requires client authentication and
will reject any connection where the client does not present a valid private key whose public
key is listed in the server's `allowed_clients.txt`.

### Generate a private key (run on the client machine)

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
chmod 600 client_private.pem
sudo mv client_private.pem /etc/ntmclient/
```

### Derive the public key for the server's allowlist

```bash
openssl pkey -in /etc/ntmclient/client_private.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 0
```

Copy the 64-character hex output to a new line in the server's `allowed_clients.txt`. See
`SERVER_DEPLOYMENT.md` Section 5 for the server-side steps.

### Key file permissions

The client checks the identity file permissions at startup and warns if the key is
group- or world-readable:

```
ntm-client: WARNING: identity key has group/world permissions; tighten with 'chmod 600'
```

Always keep the private key `600` (owner-read-only):

```bash
sudo chmod 600 /etc/ntmclient/client_private.pem
sudo chown ntmclient:ntmclient /etc/ntmclient/client_private.pem
```

---

## 6. TLS server verification

TLS verification is **mandatory**. The server always requires TLS and will reject plain TCP
connections, so the client must be configured with one of the two verification modes below.
Without either, the client attempts plain TCP and the server immediately drops the connection.

### Mode A — CA bundle verification (`--ca`)

The client verifies the server certificate against a CA file (PEM bundle). Use this when the
server uses a CA-signed certificate (Let's Encrypt or an internal CA):

```bash
ntm-client --server 192.168.1.10 --ca /etc/ssl/certs/ca-certificates.crt
```

Or for a self-signed CA that you generated yourself:

```bash
ntm-client --server 192.168.1.10 --ca /etc/ntmclient/server_cert.pem
```

### Mode B — Certificate pinning (`--server-cert`)

The client computes the SHA-256 fingerprint of the server's leaf certificate and compares it
against a locally stored copy. Use this for a self-signed certificate where you want strict
pinning rather than a CA chain:

```bash
# Copy the server certificate to each client machine once.
sudo cp server_cert.pem /etc/ntmclient/server_cert.pem

ntm-client --server 192.168.1.10 --server-cert /etc/ntmclient/server_cert.pem
```

> **When using pinning:** if you regenerate the server certificate, you must update and
> redeploy the pinned copy to every client before the old certificate expires, or clients
> will fail to reconnect.

### Hostname / IP verification

After the TLS handshake, the client always checks that the server's certificate matches the
value passed to `--server`:

- If `--server` is an **IP address**, the certificate's Subject Alternative Name IP entry
  must match.
- If `--server` is a **hostname**, the certificate's CN or SAN DNS entry must match.

Ensure the certificate's CN or SAN matches what you pass as `--server`. For a self-signed
cert generated with `-subj "/CN=192.168.1.10"`, use `--server 192.168.1.10`.

---

## 7. Configuration file

Copy and edit the example:

```bash
sudo cp ntm-client.conf.example /etc/ntmclient/ntm-client.conf
```

Full config reference:

```ini
# /etc/ntmclient/ntm-client.conf

# Server host (IP or hostname). Default 127.0.0.1.
server = 192.168.1.10

# Server ingestion port (1-65535). Default 5555.
port = 5555

# Ed25519 private key for authentication. MANDATORY — server rejects connections without it.
identity = /etc/ntmclient/client_private.pem

# TLS verification. MANDATORY — server always requires TLS; plain TCP is rejected.
# Choose one of ca or server_cert (not both).
#
# CA bundle to verify the server certificate (use for CA-signed certs):
# ca = /etc/ntmclient/server_cert.pem
#
# Server certificate for SHA-256 fingerprint pinning (use for self-signed certs):
server_cert = /etc/ntmclient/server_cert.pem

# Send buffer in bytes (4096-2097152). Default 524288 (512 KiB).
send_buffer_bytes = 524288
```

**Key precedence:** command-line flags override config file values, which override built-in
defaults.

---

## 8. First run (foreground)

Run in the foreground first to confirm capture and connectivity before daemonising:

```bash
sudo ntm-client \
  --config /etc/ntmclient/ntm-client.conf \
  --verbose
```

Expected output on stderr:
- Config values loaded (server, port, identity, TLS options).
- `ntm-client: connected to <server>:<port> (TLS, session max 6h)` on successful connect.
  If you see `(plain)` instead of `(TLS, ...)`, TLS is not configured on the client —
  the server will drop the connection. Ensure `server_cert` or `ca` is set in the config.
- One line per discovered interface that has addresses — sniffers start silently.

If the identity key permissions are too open you will see a warning; fix with `chmod 600`.
If the server rejects the connection, confirm the client's public key is in the server's
`allowed_clients.txt` and that TLS verification is configured correctly.

Press `Ctrl+C` to stop (sends `SIGINT`; the client stops all sniffers and closes the
connection cleanly). If no errors appear, proceed to daemon mode.

---

## 9. Running as a daemon

```bash
sudo ntm-client \
  --daemon \
  --config /etc/ntmclient/ntm-client.conf
```

In daemon mode:
- The process double-forks and detaches from the terminal.
- All log output goes to **syslog** (`LOG_DAEMON` facility).
- stderr/stdout are redirected to `/dev/null`.

View logs:

```bash
journalctl -t ntm-client -f        # systemd systems
sudo tail -f /var/log/daemon.log    # traditional syslog
```

---

## 10. systemd service unit

An annotated example unit file is provided at `ntm-client.service.example` in the project
root. Copy and adapt it:

```bash
sudo cp ntm-client.service.example /etc/systemd/system/ntm-client.service
```

The service runs the client as an unprivileged dedicated user and grants only the two
capabilities libpcap requires (`CAP_NET_RAW` and `CAP_NET_ADMIN`) via
`AmbientCapabilities`, without making the binary setuid or granting any other privileges.

As with the server, **`MemoryDenyWriteExecute` and `PrivateUsers` must not be enabled**:
both silently break OpenSSL TLS (see `SERVER_DEPLOYMENT.md` Section 9 for the detailed
explanation). `RestrictAddressFamilies` is set to `AF_INET AF_INET6 AF_PACKET` —
`AF_PACKET` is required because libpcap uses raw packet sockets on Linux.

Create the dedicated user and enable the service:

```bash
sudo useradd -r -s /sbin/nologin ntmclient
sudo chown -R ntmclient:ntmclient /etc/ntmclient
sudo chmod 600 /etc/ntmclient/client_private.pem

sudo systemctl daemon-reload
sudo systemctl enable --now ntm-client
sudo systemctl status ntm-client
```

---

## 11. Behaviour reference

### Interface discovery

On startup, the client calls `pcap_findalldevs` and starts one `PacketSniffer` thread per
interface that has at least one address assigned. Interfaces with no addresses (e.g. unconfigured
physical ports) are skipped. The interface list is fixed at startup; adding or removing
interfaces while the client is running requires a restart.

### What is captured

- **Link types:** Ethernet (`DLT_EN10MB`) and Linux cooked (`DLT_LINUX_SLL` / `DLT_LINUX_SLL2`).
- **Protocol filter:** IPv4 and IPv6 only (`ip or ip6` BPF filter). Non-IP traffic is discarded.
- **Snaplen:** only the first **192 bytes** of each packet are captured (enough for IP headers;
  payload content is never read).
- **Mode:** promiscuous — sees all traffic on the wire, not just traffic addressed to the host.

### What is sent to the server

For each packet, a single text line is sent:

```
D <iface> <src_ip> <dst_ip> <bytes>\n
```

No payload content, no port numbers, no protocol fields beyond IP addresses and total
packet length.

### Send buffer and batching

Captured packet metadata is accumulated in a fixed-size in-memory buffer (default 512 KiB,
configurable via `send_buffer_bytes`). A background sender thread flushes the buffer to
the server every **5 ms** or when it reaches **8 KiB**, whichever comes first. If the buffer
fills before the sender flushes, excess packets are dropped silently (a sign that
`send_buffer_bytes` should be increased or that the link to the server is saturated).

### Reconnection

If the connection to the server is lost, the sender thread reconnects automatically on the
next flush cycle (every 5 ms). There is no back-off; if the server is unreachable the client
retries continuously and logs each failure to syslog.

### TLS session lifetime

Each TLS session is capped at **6 hours**. After that the client closes and re-establishes
the connection with fresh session keys. This matches the server-side session limit.

---

## 12. Security hardening checklist

- [ ] TLS configured: `server_cert` or `ca` set (mandatory — server rejects plain TCP)
- [ ] Ed25519 identity configured: `identity` set and matching public key added to server's
  `allowed_clients.txt` (mandatory — server rejects unauthenticated connections)
- [ ] Identity key permissions are `600` (owner-read-only)
- [ ] Identity key is owned by the service user (`ntmclient`)
- [ ] Client runs as a dedicated unprivileged user with only `CAP_NET_RAW` and
  `CAP_NET_ADMIN` (not full root)
- [ ] Config file permissions prevent other users from reading the identity key path
- [ ] Server certificate renewed before expiry if using pinning (update pinned copy on each
  client at the same time)
- [ ] systemd hardening options applied (`PrivateTmp`, `ProtectSystem`, `NoNewPrivileges`,
  `RestrictAddressFamilies`)
- [ ] `MemoryDenyWriteExecute` and `PrivateUsers` are **not** set (breaks OpenSSL TLS)

---

## 13. Troubleshooting

**`pcap_findalldevs failed: permission denied` or no interfaces found**
- The process does not have packet capture privileges.
- Run with `sudo`, use `setcap`, or use the systemd service with `AmbientCapabilities`
  (see Section 4).
- Confirm at least one interface has an IP address assigned: `ip addr show`.

**`TLS handshake failed`**
- The server certificate CN or SAN does not match the `--server` value — regenerate the
  cert with the correct `-subj "/CN=<server-ip-or-hostname>"`.
- For pinning (`--server-cert`): the pinned file does not match the server's current cert.
- Confirm neither `ca` nor `server_cert` is accidentally omitted from the client config;
  without one of them the client connects plain TCP and the server immediately drops it.

**`server rejected authentication`**
- The client's public key is not in the server's `allowed_clients.txt`.
- Derive the public key hex again (`openssl pkey ... | tail -c 32 | xxd -p -c 0`) and
  add it to the server's allowlist; then send `SIGHUP` or restart the server.

**`identity key has group/world permissions` warning**
- Run `chmod 600 /etc/ntmclient/client_private.pem` to remove the warning. The client
  continues to operate, but the key is readable by other users on the system.

**Client connects but server shows no traffic**
- Run the client with `--verbose` in the foreground to confirm sniffers started.
- Check that the interfaces being captured actually carry traffic (`ip link`, `tcpdump`).
- Verify the BPF filter (`ip or ip6`) is not filtering out the traffic you expect to see.
- Confirm `send_buffer_bytes` is large enough; a saturated buffer silently drops packets.

**`connect() failed: Connection refused`**
- The server is not running or is not listening on the expected port.
- Verify the server is up: `ss -tlnp | grep 5555` on the server host.
- Check that the port matches on both sides (`port` in client config vs `--port` on server).

**Client exits with status 1 immediately**
- No interfaces with addresses were found, or the initial connection to the server failed.
- Check stderr or syslog for the specific error message.
- Run in the foreground with `--verbose` to see the full startup sequence.
