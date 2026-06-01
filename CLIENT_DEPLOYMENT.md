# ntm-client Deployment Guide

Covers deployment of `ntm-client` on **Linux** and **Windows 10/11**.

## Table of Contents

- [Linux Deployment](#linux-deployment)
  1. [Prerequisites](#1-linux-prerequisites)
  2. [Install the binary](#2-linux-install-the-binary)
  3. [Packet capture privileges](#3-linux-packet-capture-privileges)
  4. [Ed25519 identity key](#4-ed25519-identity-key-linux)
  5. [TLS server verification](#5-tls-server-verification)
  6. [Configuration file](#6-linux-configuration-file)
  7. [First run (foreground)](#7-linux-first-run-foreground)
  8. [Running as a daemon](#8-running-as-a-daemon)
  9. [systemd service unit](#9-systemd-service-unit)
  10. [Security hardening checklist](#10-linux-security-hardening-checklist)
  11. [Troubleshooting (Linux)](#11-troubleshooting-linux)

- [Windows Deployment](#windows-deployment)
  1. [Prerequisites](#1-windows-prerequisites)
  2. [Install the binary](#2-windows-install-the-binary)
  3. [Packet capture privileges](#3-windows-packet-capture-privileges)
  4. [Ed25519 identity key](#4-ed25519-identity-key-windows)
  5. [TLS server verification](#5-tls-server-verification-1)
  6. [Configuration file](#6-windows-configuration-file)
  7. [First run (foreground)](#7-windows-first-run-foreground)
  8. [Running as a background service](#8-running-as-a-background-service)
  9. [Security hardening checklist](#9-windows-security-hardening-checklist)
  10. [Troubleshooting (Windows)](#10-troubleshooting-windows)

- [Auto-Update](#auto-update)
  - [Enabling auto-update](#enabling-auto-update)
  - [How it works on Linux](#how-it-works-on-linux)
  - [How it works on Windows](#how-it-works-on-windows)
  - [Install path and permissions](#install-path-and-permissions)
  - [Windows code-signing requirement](#windows-code-signing-requirement)
  - [Troubleshooting auto-update](#troubleshooting-auto-update)

- [Common Reference](#common-reference)
  - [Behaviour reference](#behaviour-reference)
  - [Configuration keys](#configuration-keys)

---

# Linux Deployment

## 1. Linux Prerequisites

| Package | Arch Linux | Debian / Ubuntu |
|---------|------------|-----------------|
| C++17 compiler | `gcc` | `build-essential` |
| CMake ≥ 3.16 | `cmake` | `cmake` |
| OpenSSL ≥ 1.1.1 | `openssl` | `libssl-dev` |
| libpcap | `libpcap` | `libpcap-dev` |

The client does **not** require libcurl, zlib, or cpp-httplib.

---

## 2. Linux Install the Binary

> **The `.sig` file is mandatory.** `ntm-client` verifies its own ML-DSA-65
> signature at every startup and **refuses to start with FATAL** if
> `ntm-client.sig` is absent from the same directory as the binary.
> Always install the binary and its `.sig` file as a pair.

```bash
# Install binary and companion signature file (both required)
sudo install -m 755 build-linux/ntm-client-linux-amd64-<version>     /usr/local/bin/ntm-client
sudo install -m 644 build-linux/ntm-client-linux-amd64-<version>.sig /usr/local/bin/ntm-client.sig
sudo mkdir -p /etc/ntmclient
```

Recommended directory layout:

```
/usr/local/bin/ntm-client
/usr/local/bin/ntm-client.sig   # ML-DSA-65 signature — MUST be deployed with the binary
/etc/ntmclient/
    ntm-client.conf          # config file
    client_private.pem       # Ed25519 private key  (chmod 600)
    server_cert.pem          # server certificate for TLS pinning
```

---

## 3. Linux Packet Capture Privileges

`ntm-client` uses **libpcap** in promiscuous mode, which requires elevated privileges.

### Option A — Run as root (not recommended for production)

```bash
sudo ntm-client --config /etc/ntmclient/ntm-client.conf
```

### Option B — `setcap` on the binary

Grants capture capabilities permanently to the binary so any user can run it:

```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/ntm-client
# Verify:
getcap /usr/local/bin/ntm-client
# expected: /usr/local/bin/ntm-client cap_net_admin,cap_net_raw=eip
```

### Option C — systemd `AmbientCapabilities` (recommended)

Grants capabilities only to the service process at runtime without modifying the binary.
See [Section 9](#9-systemd-service-unit) for the service unit that uses this approach.

---

## 4. Ed25519 Identity Key (Linux)

### Generate a private key

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
chmod 600 client_private.pem
sudo mv client_private.pem /etc/ntmclient/
```

### Derive the public key for the server allowlist

```bash
openssl pkey -in /etc/ntmclient/client_private.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 0
```

Copy the 64-character hex output to a new line in the server's `allowed_clients.txt`.
See `SERVER_DEPLOYMENT.md` for the server-side steps.

### Key file permissions

```bash
sudo chmod 600 /etc/ntmclient/client_private.pem
sudo chown ntmclient:ntmclient /etc/ntmclient/client_private.pem
```

The client warns at startup if the key is group- or world-readable:

```
ntm-client: WARNING: identity key has group/world permissions; tighten with 'chmod 600'
```

---

## 5. TLS Server Verification

TLS is **mandatory**. The server rejects plain TCP connections. Configure one of the two
modes below.

### Mode A — CA bundle verification (`ca`)

Use when the server has a CA-signed certificate (Let's Encrypt or an internal CA):

```ini
ca = /etc/ssl/certs/ca-certificates.crt
```

Or for a self-signed CA you generated:

```ini
ca = /etc/ntmclient/server_cert.pem
```

### Mode B — Certificate pinning (`server_cert`)

Use for a self-signed certificate where you want strict SHA-256 fingerprint pinning:

```bash
# Copy the server's certificate to each client once.
sudo cp server_cert.pem /etc/ntmclient/server_cert.pem
```

```ini
server_cert = /etc/ntmclient/server_cert.pem
```

> If you regenerate the server certificate, redeploy the pinned copy to every client
> before the old certificate expires or clients will be unable to reconnect.

### Hostname / IP verification

After the TLS handshake the client always checks that the server's certificate CN or SAN
matches the `server` config value:

- IP address → the certificate's SAN IP entry must match.
- Hostname → the certificate's CN or SAN DNS entry must match.

---

## 6. Linux Configuration File

```bash
sudo cp ntm-client.conf.example /etc/ntmclient/ntm-client.conf
sudo chmod 640 /etc/ntmclient/ntm-client.conf
sudo chown root:ntmclient /etc/ntmclient/ntm-client.conf
```

Minimal production config:

```ini
# /etc/ntmclient/ntm-client.conf

server               = 192.168.1.10
port                 = 5555
identity             = /etc/ntmclient/client_private.pem
server_cert          = /etc/ntmclient/server_cert.pem
send_buffer_bytes    = 524288
```

CLI flags override config values, which override built-in defaults.

---

## 7. Linux First Run (Foreground)

```bash
sudo ntm-client --config /etc/ntmclient/ntm-client.conf --verbose
```

Expected output:

```
ntm-client: loaded config from /etc/ntmclient/ntm-client.conf (...)
ntm-client: connecting to 192.168.1.10:5555 (identity=..., ...)
ntm-client: connected to 192.168.1.10:5555 (TLS, session max 6h)
```

- If you see `(plain)` instead of `(TLS, ...)` — TLS is not configured; the server will
  drop the connection. Add `server_cert` or `ca` to the config.
- Press `Ctrl+C` to stop cleanly (`SIGINT`).

---

## 8. Running as a Daemon

```bash
sudo ntm-client --daemon --config /etc/ntmclient/ntm-client.conf
```

In daemon mode the process double-forks, detaches from the terminal, and logs to **syslog**
(`LOG_DAEMON` facility). View logs:

```bash
journalctl -t ntm-client -f          # systemd systems
sudo tail -f /var/log/daemon.log      # traditional syslog
```

---

## 9. systemd Service Unit

```bash
sudo cp ntm-client.service.example /etc/systemd/system/ntm-client.service
```

The service runs as an unprivileged dedicated user and grants only `CAP_NET_RAW` and
`CAP_NET_ADMIN` via `AmbientCapabilities`.

> **Note:** Do **not** set `MemoryDenyWriteExecute` or `PrivateUsers` — both silently break
> OpenSSL TLS. `RestrictAddressFamilies` must include `AF_PACKET` for libpcap.

```bash
sudo useradd -r -s /sbin/nologin ntmclient
sudo chown -R ntmclient:ntmclient /etc/ntmclient
sudo chmod 600 /etc/ntmclient/client_private.pem

sudo systemctl daemon-reload
sudo systemctl enable --now ntm-client
sudo systemctl status ntm-client
```

---

## 10. Linux Security Hardening Checklist

- [ ] TLS configured: `server_cert` or `ca` set (server rejects plain TCP)
- [ ] Ed25519 identity configured: `identity` set and public key in server's `allowed_clients.txt`
- [ ] Identity key permissions `600` (owner-read-only)
- [ ] Identity key owned by the service user (`ntmclient`)
- [ ] Client runs as a dedicated unprivileged user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`
- [ ] Config file permissions prevent other users reading identity key path
- [ ] Server certificate renewed before expiry if using pinning
- [ ] systemd hardening applied (`PrivateTmp`, `ProtectSystem`, `NoNewPrivileges`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET`)
- [ ] `MemoryDenyWriteExecute` and `PrivateUsers` are **not** set
- [ ] Binary and its `.sig` file both installed in the same directory (`/usr/local/bin/ntm-client` and `/usr/local/bin/ntm-client.sig`)
- [ ] Binary installed in `/opt/ntm/bin/` owned by `ntmclient` user (required for auto-update)

---

## 11. Troubleshooting (Linux)

**`FATAL — binary signature verification failed` (exits immediately)**
`ntm-client.sig` is missing from the same directory as the binary, or does not match
the binary (e.g. the binary was replaced without its companion `.sig`).
Both files must be deployed together — re-run the `install` commands from
[Section 2](#2-linux-install-the-binary) with the matching versioned pair:
```bash
sudo install -m 755 build-linux/ntm-client-linux-amd64-<version>     /usr/local/bin/ntm-client
sudo install -m 644 build-linux/ntm-client-linux-amd64-<version>.sig /usr/local/bin/ntm-client.sig
```

**`pcap_findalldevs failed: permission denied`**
The process has no packet capture privileges. Run with `sudo`, use `setcap`, or use the
systemd service with `AmbientCapabilities` (Section 3).

**`TLS handshake failed`**
Server certificate CN/SAN does not match the `server` value, or the pinned cert is stale.
Regenerate the server cert with the correct `-subj "/CN=<server-ip>"` and redeploy.

**`server rejected authentication`**
The client's public key is not in the server's `allowed_clients.txt`. Re-derive the hex key
and add it to the allowlist; restart or `SIGHUP` the server.

**`identity key has group/world permissions` warning**
Run `chmod 600 /etc/ntmclient/client_private.pem`.

**Client connects but server shows no traffic**
Run with `--verbose` to confirm sniffers started. Verify interfaces have addresses
(`ip addr show`) and carry traffic (`tcpdump -i <iface>`).

**`connect() failed: Connection refused`**
Server is not running or port mismatch. Check: `ss -tlnp | grep 5555` on the server host.

---

# Windows Deployment

## 1. Windows Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows 10 (1903+) or Windows 11 | x86-64 only |
| **Npcap** | Packet capture driver — **must be installed** |
| Administrator account | Required for packet capture |
| OpenSSL for Windows | Only needed to generate the Ed25519 key |

### Install Npcap

Download the Npcap installer from **https://npcap.com/#download** and run it.
Default installation options are sufficient. Npcap provides `wpcap.dll`, which
`ntm-client.exe` loads at startup.

> Npcap is a kernel-mode driver and cannot be statically linked into the exe — it must be
> installed on every machine running `ntm-client.exe`. The installer is ~1 MB and supports
> **silent installation** for automated deployment:
> ```
> npcap-1.xx.exe /S
> ```

### Install OpenSSL (for key generation only)

`ntm-client.exe` does **not** require OpenSSL to be installed at runtime (it is statically
linked). OpenSSL is only needed once to generate the Ed25519 identity key.

Options:
- **Git for Windows** ships with `openssl.exe` — use the Git Bash shell.
- **Win64 OpenSSL** from https://slproweb.com/products/Win32OpenSSL.html
- **Windows Subsystem for Linux (WSL)** — use the Linux `openssl` command.

---

## 2. Windows Install the Binary

The recommended production layout is the **hardened 4-directory structure** created by
`install-service-windows.ps1` (see [Section 8](#8-running-as-a-background-service)).
For a quick manual install without service mode:

```
C:\Program Files\ntm-client\
    ntm-client.exe
    ntm-client.exe.sig        ← ML-DSA-65 signature — MUST be deployed with the binary

C:\ProgramData\ntm-client\
    ntm-client.conf
    server_cert.pem           ← optional pinned server certificate

C:\ProgramData\ntm-client\secrets\
    client_private.pem        ← Ed25519 identity key (restrict ACL — see Section 4)
```

> **The `.sig` file is mandatory.** `ntm-client.exe` verifies its own ML-DSA-65
> signature at every startup (before any other initialisation) and **refuses to
> start with a FATAL error** if `ntm-client.exe.sig` is absent or invalid. Always
> deploy the binary and its `.sig` file as a pair.

Using PowerShell (run as Administrator):

```powershell
New-Item -ItemType Directory -Path "C:\Program Files\ntm-client"
# Rename versioned binary and sig to the install names
Copy-Item ntm-client-windows-amd64-<version>.exe     "C:\Program Files\ntm-client\ntm-client.exe"
Copy-Item ntm-client-windows-amd64-<version>.exe.sig "C:\Program Files\ntm-client\ntm-client.exe.sig"

New-Item -ItemType Directory -Path "C:\ProgramData\ntm-client"
New-Item -ItemType Directory -Path "C:\ProgramData\ntm-client\secrets"
```

> If using `install-service-windows.ps1`, the script copies both files automatically
> and will error if the `.sig` is missing.

---

## 3. Windows Packet Capture Privileges

On Windows, `ntm-client.exe` must be run as **Administrator** for Npcap to open interfaces
in promiscuous mode.

To launch from an elevated Command Prompt:

```cmd
"C:\Program Files\ntm-client\ntm-client.exe" --config "C:\ProgramData\ntmclient\ntm-client.conf"
```

Or right-click the executable and choose **Run as administrator**.

> When installed as a Windows SCM service (see [Section 8](#8-running-as-a-background-service)),
> the service runs as the `NT SERVICE\ntm-client` virtual account which has the necessary
> Npcap privileges.

---

## 4. Ed25519 Identity Key (Windows)

Place the key in `C:\ProgramData\ntm-client\secrets\` — the hardened install layout
restricts this directory to the service identity and Administrators (see Section 8).

### Using Git Bash (recommended)

Open **Git Bash** and run:

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
```

Move the key to the secrets directory:

```bash
mv client_private.pem /c/ProgramData/ntm-client/secrets/client_private.pem
```

### Using WSL

```bash
openssl genpkey -algorithm ED25519 \
  -out /mnt/c/ProgramData/ntm-client/secrets/client_private.pem
```

### Derive the public key for the server allowlist

```bash
openssl pkey -in /c/ProgramData/ntm-client/secrets/client_private.pem \
    -pubout -outform DER | tail -c 32 | xxd -p -c 0
```

Copy the 64-character hex output to the server's `allowed_clients.txt`.

### Protect the key file

If you used `install-service-windows.ps1`, the `secrets\` directory ACL is set
automatically (service: read-only; `BUILTIN\Users`: denied). For a manual install,
set permissions with PowerShell (run as Administrator):

```powershell
$path = "C:\ProgramData\ntm-client\secrets\client_private.pem"
$acl  = Get-Acl $path

# Remove inherited permissions and existing entries
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

# Grant read access to SYSTEM and Administrators only
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","Read","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators","Read","Allow")))

Set-Acl $path $acl
```

> `ntm-client.exe` will print a warning to protect the key file at startup if it
> detects that non-owner accounts have read access.

---

## 5. TLS Server Verification (Windows)

Three modes are available. Mode A (Windows Certificate Store) is recommended for servers with publicly-trusted certificates.

### Mode A — Windows Certificate Store (recommended)

Uses the certificates managed by Windows itself — the same roots that browsers and Windows Update trust. No files to manage; always reflects the current OS trust anchors.

```ini
ca = system
```

### Mode B — CA bundle file

Point to a PEM file containing the CA certificates to trust:

```ini
ca = C:\ProgramData\ntm-client\ca-bundle.pem
```

### Mode C — Certificate pinning (recommended for self-signed certs)

Copy the server certificate to the client machine:

```powershell
Copy-Item server_cert.pem "C:\ProgramData\ntm-client\server_cert.pem"
```

```ini
server_cert = C:\ProgramData\ntm-client\server_cert.pem
```

---

## 6. Windows Configuration File

Create `C:\ProgramData\ntm-client\ntm-client.conf`:

```ini
# ntm-client.conf — Windows paths use backslash or forward slash (both work)

server               = 192.168.1.10
port                 = 5555
identity             = C:\ProgramData\ntm-client\secrets\client_private.pem
ca                   = system
send_buffer_bytes    = 524288

# transport = tcp      # direct TLS connection (LAN or VPN, default)
# transport = websocket  # required when server is behind Cloudflare or any HTTP proxy
```

| Key | Values | Default | Notes |
|-----|--------|---------|-------|
| `transport` | `tcp` \| `websocket` (alias `ws`) | `tcp` | **`tcp`** — direct TLS; use when the client can reach the server port directly (LAN, VPN, or port-forwarded). **`websocket`** — required when the server is behind Cloudflare or any HTTP/HTTPS reverse proxy. A misconfigured transport causes the client to receive an HTTP error response instead of the auth nonce, which presents as `authentication rejected`. See the [Cloudflare/proxy note](#authentication-rejected--alpn-warning) in Troubleshooting. |

> Both `C:\path\to\file` and `C:/path/to/file` are accepted.

---

## 7. Windows First Run (Foreground)

Open a **Command Prompt as Administrator** and run:

```cmd
"C:\Program Files\ntm-client\ntm-client.exe" ^
    --config "C:\ProgramData\ntm-client\ntm-client.conf" ^
    --verbose
```

Expected output on the console:

```
ntm-client: loaded config from C:\ProgramData\ntm-client\ntm-client.conf (...)
ntm-client: connecting to 192.168.1.10:5555 (identity=..., ...)
ntm-client: connected to 192.168.1.10:5555 (TLS, session max 6h)
```

- All log output goes to **stderr** (the console window). There is no syslog on Windows.
- Press `Ctrl+C` to stop cleanly.
- The `--daemon` flag is **not supported** on Windows and will print a warning.
- If the process exits immediately with `FATAL — binary signature verification failed`, the
  `ntm-client.exe.sig` file is missing from the same directory as the binary. Copy it there
  (see [Section 2](#2-windows-install-the-binary)).

### Interface names

On Windows, Npcap enumerates interfaces using internal device paths such as:

```
\Device\NPF_{4A5B6C7D-...}
```

These are logged at startup alongside the friendly name (e.g. `Ethernet`, `Wi-Fi`).
The interface list is fixed at startup; a restart is required if interfaces change.

---

## 8. Running as a Background Service

`ntm-client` supports native **Windows SCM (Service Control Manager)** service mode via the
`--service` flag. This is the recommended production deployment method: it integrates with
`sc.exe`, Event Viewer, and the auto-update restart mechanism.

### Install (run as Administrator)

```powershell
.\scripts\install-service-windows.ps1
```

This script:
1. Creates the hardened 4-directory layout (see [Hardened install layout](#hardened-install-layout) below).
2. Copies the latest build from `build-windows\` to `C:\Program Files\ntm-client\ntm-client.exe`.
3. Registers the service (`sc create ntm-client ...`).
4. Sets failure-action restart policy (5 s / 5 s / 30 s). The auto-updater calls
   `ExitProcess(0)` after a successful update; the SCM restart policy relaunches the service
   with the new binary automatically.
5. Applies hardened ACLs (see below).
6. Starts the service.

**Verify:**
```powershell
Get-Service ntm-client
sc.exe query ntm-client
```

**Edit config then restart:**
```powershell
notepad "C:\ProgramData\ntm-client\ntm-client.conf"
Restart-Service ntm-client
```

**Uninstall** (preserves config and identity key):
```powershell
.\scripts\uninstall-service-windows.ps1
```

### Manual service control

```powershell
Start-Service ntm-client
Stop-Service  ntm-client
Restart-Service ntm-client
```

### Hardened install layout

```
C:\Program Files\ntm-client\           ← exe + sig (service: rename + execute rights)
    ntm-client.exe
    ntm-client.exe.sig                 ← ML-DSA-65 signature (deployed with binary; replaced by auto-update)
    ntm-client.exe.old                 ← leftover after auto-update (cleaned on restart)

C:\ProgramData\ntm-client\             ← per-machine config and state (service: read-only)
    ntm-client.conf
    server_cert.pem                    ← optional pinned server certificate
    ntm-client.update-state            ← auto-update timestamp (service: write)

C:\ProgramData\ntm-client\staging\     ← pending update downloads (service: full access)
    ntm-client-pending.exe             ← in-progress download (cleaned on restart)

C:\ProgramData\ntm-client\secrets\     ← Ed25519 identity key (service: read; Users: denied)
    client_private.pem
```

| Directory | Service ACE | Why |
|---|---|---|
| `Program Files\ntm-client\` | `(OI)(CI)M` (modify) | `MoveFileExW` needs rename rights to swap the running binary |
| `ProgramData\ntm-client\` | `(OI)(CI)RX` (read+execute) | Read config and certs; state file write handled per-file |
| `ProgramData\ntm-client\staging\` | `(OI)(CI)F` (full) | Download area; no exec needed in install dir |
| `ProgramData\ntm-client\secrets\` | `(OI)(CI)R` (read only) | Identity key must not be writable by the service itself |

`BUILTIN\Users` is explicitly denied on `secrets\`. Run `icacls "C:\ProgramData\ntm-client\secrets"` to verify.

### Appendix: Task Scheduler (legacy / non-service alternative)

If you cannot run the install script or prefer not to use SCM service mode, you can use
Task Scheduler with the SYSTEM account. This approach does **not** support the auto-update
restart mechanism (the SCM restart policy is not available).

```powershell
$action = New-ScheduledTaskAction `
    -Execute  '"C:\Program Files\ntm-client\ntm-client.exe"' `
    -Argument '--config "C:\ProgramData\ntm-client\ntm-client.conf"'
$trigger   = New-ScheduledTaskTrigger -AtStartup
$settings  = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "ntm-client" -Action $action `
    -Trigger $trigger -Settings $settings -Principal $principal -Force
```

---

## 9. Windows Security Hardening Checklist

- [ ] Npcap installed (required for packet capture); kept up to date
- [ ] Service installed via `install-service-windows.ps1` (hardened layout, ACLs, and failure-action restart applied)
- [ ] TLS configured: `server_cert` or `ca` set (server rejects plain TCP)
- [ ] Ed25519 identity configured: `identity` set and public key in server's `allowed_clients.txt`
- [ ] `client_private.pem` placed in `C:\ProgramData\ntm-client\secrets\` — verify ACL:
  `icacls "C:\ProgramData\ntm-client\secrets\client_private.pem"` shows only `SYSTEM` and `Administrators`; `BUILTIN\Users` denied
- [ ] Server certificate renewed before expiry if using pinning (redeploy to each client)
- [ ] Binary Authenticode code-signing optional but recommended when you have a code-signing certificate (see [Windows code-signing requirement](#windows-code-signing-requirement))

---

## 10. Troubleshooting (Windows)

**`FATAL — binary signature verification failed` (exits immediately)**
- `ntm-client.exe.sig` is missing from the same directory as the binary, or
  does not match the binary (e.g. the binary was replaced without its `.sig`).
- Both files must be deployed together — copy the matching `.sig` file alongside
  the `.exe` (see [Section 2](#2-windows-install-the-binary)).
- If using `install-service-windows.ps1`, it will fail at startup if the `.sig`
  was not found next to the source binary in `build-windows\`.

**`pcap_findalldevs failed` or no interfaces captured**
- Npcap is not installed, or the process is not running as Administrator.
- Verify Npcap is installed: check **Add/Remove Programs** for "Npcap".
- Run `ntm-client.exe` from an elevated Command Prompt.

**`TLS handshake failed`**
- Server certificate CN/SAN does not match the `server` value.
- Pinned cert (`server_cert`) does not match the server's current certificate.
- Confirm the path in `server_cert` or `ca` is correct and the file is readable by SYSTEM.

**`server rejected authentication` / `authentication rejected`** {#authentication-rejected--alpn-warning}

There are two distinct causes — check the verbose log to distinguish them.

*Cause A — wrong transport (Cloudflare / HTTP proxy):*
- Run with `--verbose` and look for this warning:
  ```
  WARNING — server selected ALPN='(none)' not 'ntm-wire'. Use transport=websocket to traverse Cloudflare.
  ```
  When present, the client is connecting through an HTTP proxy (Cloudflare, nginx, etc.) that
  does not forward raw TLS. Add `transport = websocket` to the config:
  ```ini
  transport = websocket
  ```
  The WebSocket upgrade request passes through HTTP proxies; the raw TLS auth byte (`0x03`)
  does not. Without this setting the client receives an HTTP 4xx error response in place of
  the 32-byte auth nonce, which it signs and sends — causing immediate rejection.

*Cause B — key not registered on server:*
- Derive the 64-char hex public key from the client's private key:
  ```bash
  # In MSYS2 mingw64 shell:
  openssl pkey -in /c/ProgramData/ntm-client/secrets/client_private.pem \
    -pubout -outform DER | od -A n -t x1 | tr -d ' \n' | tail -c 64
  ```
  Add that 64-char hex as a new line in the server's `allowed_keys` file and reload the
  server (or send SIGHUP if supported).

**`ntm-client: NOTE: ensure identity key is protected via NTFS permissions`**
- Set the ACL on `client_private.pem` as shown in Section 4.

**Client connects but server shows no traffic**
- Run with `--verbose` to confirm sniffers started and interfaces were found.
- Confirm Npcap is installed and the process is running as Administrator.
- Check that the listed interfaces are the ones carrying the traffic you expect.

**`connect() failed (WSA ...)`**
- Server is not running or the port is blocked by Windows Firewall.
- From server v1.15.0, **only one port needs to be open** (default `5555`) — it serves both
  data ingestion and the HTTPS dashboard via TLS ALPN. If you previously opened a separate
  port for the dashboard (typically `8443`), that rule is no longer needed.
- Add an inbound rule on the **server** machine:
  ```
  netsh advfirewall firewall add rule name="ntm-server" dir=in action=allow protocol=TCP localport=5555
  ```
- Verify the server is reachable: `Test-NetConnection -ComputerName 192.168.1.10 -Port 5555`.

**The scheduled task starts but exits immediately**
- Enable output redirection in the task action (see Section 8) to capture the error message.
- Run the binary manually from an elevated prompt first to see the error on screen.

**`--daemon` flag has no effect**
- Daemon mode is not supported on Windows. The flag prints a warning and the process
  continues in the foreground. Use `--service` with the SCM install script for background
  operation (see [Section 8](#8-running-as-a-background-service)).

**`ntm-client: config: 'web_port' is deprecated since server v1.15.0`**
- You have a `web_port = ...` line in your config file left over from a pre-v1.15.0 server.
  The value is silently ignored (the auto-updater now uses `port`). Remove the `web_port`
  line to suppress this warning.

---

# Auto-Update

`ntm-client` supports automatic binary updates on Linux and Windows. The feature is **off by
default** and must be explicitly enabled. See `docs/auto-update.md` for full server-side
setup instructions.

## Enabling auto-update

Add the following to the client config file:

```ini
# Enable automatic binary updates (opt-in, default: false)
auto_update = true
```

> **Server v1.15.0+ (ALPN port consolidation):** The HTTPS dashboard and data-ingestion
> channel now share a single TLS port via ALPN. The update check connects to the same
> `port` value used for data ingestion (default `5555`). **Remove any `web_port` line**
> from the client config — it is no longer needed and the server ignores it.
>
> **Upgrading from server < 1.15.0:** Keep `web_port = <your-old-web_port>` (typically
> `web_port = 8443`) until you upgrade the server. Remove the line after upgrading.

The client uses the same `server`, `server_cert`, and `ca` settings already configured for
TLS. No additional certificate configuration is needed. The first update check runs
approximately 23 hours after startup.

## How it works on Linux

1. The client checks `/api/update/check` on the server's HTTPS API every 23 hours.
2. If a newer binary is available, it is downloaded and written to a `.pending` file in the
   same directory as the running binary (located via `/proc/self/exe`).
3. The SHA-256 digest of the download is verified against the server's manifest. Mismatch
   aborts the update and deletes the pending file.
4. The pending binary is made executable, then atomically renamed over the running binary.
5. The client calls `execv` on itself — the new binary is loaded in place with the same
   process ID. systemd does not need to restart the unit.

On startup, any stale `.pending` file from a previously interrupted update is deleted
automatically.

## How it works on Windows

1. Same 23-hour check cycle against `/api/update/check`.
2. The server response is rejected if it reports a binary larger than **64 MiB** — a
   safety cap against a rogue server advertising an unbounded download.
3. Download written to `ntm-client-pending.exe` in
   `%ProgramData%\ntm-client\staging\` (created automatically if absent). Separating
   the staging directory from the install directory means the service account only needs
   write access to `%ProgramData%\ntm-client\staging\` during the download phase —
   not to the install directory (`Program Files`).
4. SHA-256 and ML-DSA-65 signature verification identical to Linux; failure aborts and
   deletes the pending file.
5. `MoveFileExW` (with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED`) renames the
   running binary to `ntm-client.exe.old`, then moves the pending file to
   `ntm-client.exe`. `MOVEFILE_COPY_ALLOWED` handles the cross-volume case when
   `%ProgramData%` and `Program Files` are on different drives.
6. The new binary is smoke-tested: the client launches it with `--version` and waits up
   to 10 seconds for exit 0. If the smoke test fails, the old binary is restored from
   `ntm-client.exe.old` and the update is skipped.
7. The client calls `ExitProcess(0)`. Task Scheduler / SCM detects the exit and
   relaunches the process within approximately one minute with the new binary.

On startup, stale `ntm-client-pending.exe` files (in both the staging and install
directories) and `ntm-client.exe.old` from a previous update are deleted automatically.

### Optional: Authenticode verification

Build with `-DNTM_REQUIRE_AUTHENTICODE=ON -DNTM_AUTHENTICODE_SUBJECT="CN=Your Org"` to
require that every downloaded binary passes `WinVerifyTrust` before it is applied.
Disabled by default; full subject-string matching is deferred to a follow-up release.

## Install path and permissions

Auto-update requires the service user to have write access to the binary directory so that
the rename operations succeed without elevated privileges at update time.

**Linux — recommended path:** `/opt/ntm/bin/ntm-client`

```bash
sudo mkdir -p /opt/ntm/bin
sudo install -m 755 build-linux/ntm-client /opt/ntm/bin/ntm-client
sudo chown ntmclient:ntmclient /opt/ntm/bin /opt/ntm/bin/ntm-client
```

The `ntmclient` service user must own **both** the binary and the containing directory.

**Windows — recommended path:** `C:\Program Files\ntm-client\ntm-client.exe`

Use `install-service-windows.ps1` (see [Section 8 of Windows Deployment](#8-running-as-a-background-service)).
The script creates the full hardened 4-directory layout and sets the ACLs that allow
the `NT SERVICE\ntm-client` virtual account to rename the exe during auto-update without
requiring write access to the rest of `Program Files`.

The key points of the hardened layout for auto-update:
- The binary lives in `C:\Program Files\ntm-client\` with `(OI)(CI)M` (modify/rename rights) for the service SID — enough for `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.
- Pending downloads land in `C:\ProgramData\ntm-client\staging\` (full access for the service), keeping the download phase out of the install directory.
- `MOVEFILE_COPY_ALLOWED` is passed so cross-volume moves (if `ProgramData` and `Program Files` are on different drives) fall back to a copy+delete.

> **NOTE:** Installing `ntm-client.exe` in a directory where the service account lacks
> rename rights will cause auto-update to fail silently with `MoveFile failed`.
> Always use `install-service-windows.ps1` or apply equivalent ACLs manually.

See also:
- Linux security hardening: [Section 10](#10-linux-security-hardening-checklist)
- Windows security hardening: [Section 9](#9-windows-security-hardening-checklist)

## Windows code-signing requirement

Windows Defender and SmartScreen block execution of unsigned binaries. All Windows client
binaries distributed via auto-update must be **Authenticode code-signed** with a trusted
code-signing certificate. Unsigned binaries will be quarantined before the client can apply
them.

Sign the binary before placing it in the server's `update_dir`:

```powershell
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
    /n "Your Organization Name" `
    ntm-client-windows-amd64-<version>.exe
```

## Troubleshooting auto-update

**Binary not updating**
- Confirm `auto_update=true` is set (default is `false`). Checks run every 23 hours.
- Verify the binary in `update_dir` follows the naming convention exactly:
  `ntm-client-linux-amd64-<version>` or `ntm-client-windows-amd64-<version>.exe`.
- Confirm a manifest scan was run on the server after placing the binary.
- Confirm the binary version in the filename is higher than the client's current version.
- On Windows: if your build uses `-DNTM_REQUIRE_AUTHENTICODE=ON`, verify the binary is
  Authenticode code-signed. Standard builds do not enforce Authenticode (off by default).

**Stale pending file (Linux)**
A `.pending` file in the binary directory indicates an interrupted update. The client removes
it automatically on next startup. To remove manually:
```bash
rm /opt/ntm/bin/ntm-client.pending
```

**Stale .old file (Windows)**
An `ntm-client.exe.old` file in the binary directory indicates a completed update. The client
removes it on next startup. To remove manually:
```powershell
Remove-Item "C:\Program Files\ntm-client\ntm-client.exe.old"
```

**Stale pending file (Windows)**
`ntm-client-pending.exe` in `%ProgramData%\ntm-client\staging\` indicates an interrupted
download. Deleted automatically on next startup. To remove manually:
```powershell
Remove-Item "$env:ProgramData\ntm-client\staging\ntm-client-pending.exe" -ErrorAction SilentlyContinue
```

**"server reported size N exceeds 64 MiB cap"**
The update manifest on the server contains an unusually large `size` value. Verify the
server-side manifest is correct. Legitimate ntm-client binaries are well under 64 MiB.

**"rename failed: Permission denied" (Linux)**
The service user does not own the binary directory. Re-apply the `chown` command from the
[Install path and permissions](#install-path-and-permissions) section above.

**"MoveFile failed" (Windows)**
The SYSTEM account does not have write permission on the binary directory. Re-apply the
`icacls` commands from the [Install path and permissions](#install-path-and-permissions)
section above.

**Update check returns 404**
`update_dir` is not set in the server config, or the server was not restarted after setting
it. The `/api/update/*` endpoints are only registered when `update_dir` is non-empty.

---

# Common Reference

## Behaviour Reference

### Interface discovery

At startup `ntm-client` calls `pcap_findalldevs` and starts one sniffer thread per
interface that has at least one address assigned. Interfaces with no addresses are skipped.
The interface list is **fixed at startup** — adding or removing interfaces while the client
is running requires a restart.

### What is captured

| Property | Value |
|----------|-------|
| Link types (Linux) | Ethernet (`DLT_EN10MB`), Linux cooked (`DLT_LINUX_SLL`, `DLT_LINUX_SLL2`) |
| Link types (Windows) | Ethernet (`DLT_EN10MB`) |
| Protocol filter | IPv4 and IPv6 only (`ip or ip6` BPF filter) |
| Snaplen | First **192 bytes** per packet — enough for IP headers; payload is never read |
| Mode | Promiscuous — sees all traffic on the wire, not just traffic to/from the host |

### What is sent to the server

For each packet, a single text line:

```
D <iface> <src_ip> <dst_ip> <bytes>\n
```

No payload, no port numbers, no protocol fields beyond IP addresses and total packet size.

### Send buffer and batching

Packet metadata accumulates in a fixed-size in-memory buffer (default 512 KiB,
configurable via `send_buffer_bytes`). A background thread flushes the buffer every
**5 ms** or when it reaches **8 KiB**, whichever comes first. Packets are silently
dropped if the buffer fills before the sender can flush.

### Reconnection

If the server connection is lost the sender thread reconnects automatically on the next
flush cycle (~5 ms). There is no exponential back-off; failed attempts are logged
continuously.

### TLS session lifetime

Each TLS session is capped at **6 hours**. After that the client closes and re-establishes
the connection with fresh session keys.

### Network change detection

| Platform | Method |
|----------|--------|
| Linux | `RTNETLINK` (`RTMGRP_LINK`, `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR`), with `getifaddrs` polling fallback |
| Windows | `NotifyIpInterfaceChange`, with `GetAdaptersAddresses` polling fallback |

On any detected change the client re-announces its external IP and LAN addresses to the
server (subject to a 30-second client-side cooldown).

---

## Configuration Keys

All keys are set in the config file (`key = value`) or overridden by CLI flags.

| Key | CLI flag | Default | Description |
|-----|----------|---------|-------------|
| `server` | `--server` | `127.0.0.1` | Server hostname or IP |
| `port` | `--port` | `5555` | Server ingestion port (1–65535) |
| `identity` | `--identity` | *(none)* | Path to Ed25519 private key PEM |
| `ca` | `--ca` | *(none)* | CA bundle path, or `system` to use the OS trust store (Windows Certificate Store on Windows; system CA bundle on Linux) |
| `server_cert` | `--server-cert` | *(none)* | Server cert for SHA-256 fingerprint pinning |
| `send_buffer_bytes` | — | `524288` | Send buffer size in bytes (4096–2097152) |
| `external_ip_url` | — | `http://checkip.amazonaws.com/` | URL used to detect external/WAN IP |
| `external_ip_timeout_ms` | — | `5000` | Timeout for external IP check (500–30000 ms) |
| `reconnect_attempts` | `--reconnect-attempts` | `10` | Max consecutive reconnect failures before exit (1–1000) |
| `reconnect_interval_sec` | `--reconnect-interval` | `60` | Seconds between reconnect attempts (1–3600) |
| `transport` | `--transport` | `tcp` | Connection transport: `tcp` (raw TLS, default) or `websocket` (WebSocket over TLS, for Cloudflare tunnels and HTTP proxies) |
| `compress` | `--no-compress` (inverse) | `true` | Enable zlib compression on the data phase. Set `compress=false` or pass `--no-compress` to disable. Supported on both Linux (system zlib) and Windows (vendored miniz). |
| `auto_update` | — | `false` | Enable daily binary self-update check (opt-in) |
| `web_port` | — | `8443` | *(Deprecated — server v1.15.0+)* HTTPS port used by auto-update to reach `/api/update/check`. Before server v1.15.0 this matched `web_port` in the server config (default `8443`). From server v1.15.0+ the dashboard shares the data-ingestion `port` via ALPN — remove this key from the config when connecting to a v1.15.0+ server. |
| `verbose` | `--verbose` | `false` | Enable verbose logging |
| `log_dir` | — | *(platform default — see below)* | Directory for client log files. Empty string uses the platform default. |
| `log_level` | — | `Info` | Initial log verbosity: `Info`, `Warn`, or `Err`. Can be changed at runtime from the admin dashboard without restarting the client. |
| `agg_target_lines_per_sec` | — | `500` | Target aggregated D-lines per second emitted to the server. The adaptive interval controller adjusts the flush interval to meet this target. |
| `agg_min_interval_ms` | — | `100` | Minimum time between aggregation flushes (milliseconds). Lower values reduce latency but increase server load. |
| `agg_max_interval_ms` | — | `5000` | Maximum time between aggregation flushes (milliseconds). Acts as a heartbeat when traffic is idle. |
| `agg_max_flows` | — | `10000` | Maximum distinct (iface, src, dst) flows per flush window. Reaching this limit triggers an early flush regardless of the interval. |

Precedence: **CLI flags** > **config file** > **built-in defaults**.

### File logging default paths

| Platform | Mode | Default `log_dir` |
|----------|------|-------------------|
| Linux | Daemon (`--daemon`) | `/var/log/ntm-client/` |
| Linux | Foreground (user) | `$XDG_STATE_HOME/ntm-client/logs/` or `~/.local/state/ntm-client/logs/` |
| Windows | Service | `%PROGRAMDATA%\ntm-client\logs\` |
| Windows | User | `%LOCALAPPDATA%\ntm-client\logs\` |

File logging is enabled by default when a valid log directory can be determined.  
Set `log_dir=` (empty) to use the platform default, or specify an absolute path.

Log files are named `ntm-client-YYYY-MM-DD.log`. The client:
- **Retains 3 days** of log files (older files are deleted on startup and daily at midnight).
- **Caps each file at 50 MB** — when the cap is reached, the oldest half of the file is discarded in place to make room for new entries.
- **Supports runtime level changes** via the admin dashboard (Manage Clients → select client → Logs panel). The change takes effect immediately without restarting the client.
