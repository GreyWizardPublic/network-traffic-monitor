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

```bash
sudo install -m 755 build-linux/ntm-client /usr/local/bin/ntm-client
sudo mkdir -p /etc/ntmclient
```

Recommended directory layout:

```
/usr/local/bin/ntm-client
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
- [ ] Binary installed in `/opt/ntm/bin/` owned by `ntmclient` user (required for auto-update)

---

## 11. Troubleshooting (Linux)

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

Copy `ntm-client.exe` to a permanent location:

```
C:\Program Files\ntm-client\ntm-client.exe
```

Create a configuration directory:

```
C:\ProgramData\ntmclient\
    ntm-client.conf
    client_private.pem
    server_cert.pem
```

Using PowerShell (run as Administrator):

```powershell
New-Item -ItemType Directory -Path "C:\Program Files\ntm-client"
Copy-Item ntm-client.exe "C:\Program Files\ntm-client\"

New-Item -ItemType Directory -Path "C:\ProgramData\ntmclient"
```

---

## 3. Windows Packet Capture Privileges

On Windows, `ntm-client.exe` must be run as **Administrator** for Npcap to open interfaces
in promiscuous mode.

To launch from an elevated Command Prompt:

```cmd
"C:\Program Files\ntm-client\ntm-client.exe" --config "C:\ProgramData\ntmclient\ntm-client.conf"
```

Or right-click the executable and choose **Run as administrator**.

> When running as a Windows Service via Task Scheduler (see Section 8), the task is
> configured to run with the SYSTEM account which has the necessary privileges.

---

## 4. Ed25519 Identity Key (Windows)

### Using Git Bash (recommended)

Open **Git Bash** and run:

```bash
openssl genpkey -algorithm ED25519 -out client_private.pem
```

Move the key to the config directory:

```bash
mv client_private.pem /c/ProgramData/ntmclient/client_private.pem
```

### Using WSL

```bash
openssl genpkey -algorithm ED25519 -out /mnt/c/ProgramData/ntmclient/client_private.pem
```

### Derive the public key for the server allowlist

```bash
openssl pkey -in /c/ProgramData/ntmclient/client_private.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 0
```

Copy the 64-character hex output to the server's `allowed_clients.txt`.

### Protect the key file

Set NTFS permissions so only the SYSTEM account and Administrators can read the key.
Using PowerShell (run as Administrator):

```powershell
$path = "C:\ProgramData\ntmclient\client_private.pem"
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

> `ntm-client.exe` will print a reminder to protect the key file at startup. Restricting
> the permissions via the ACL above silences this reminder in future versions.

---

## 5. TLS Server Verification (Windows)

Same two modes as Linux — configure one in the config file using Windows paths.

### Mode A — CA bundle verification

```ini
ca = C:\ProgramData\ntmclient\server_cert.pem
```

### Mode B — Certificate pinning (recommended for self-signed certs)

Copy the server certificate to the client machine:

```powershell
Copy-Item server_cert.pem "C:\ProgramData\ntmclient\server_cert.pem"
```

```ini
server_cert = C:\ProgramData\ntmclient\server_cert.pem
```

---

## 6. Windows Configuration File

Create `C:\ProgramData\ntmclient\ntm-client.conf`:

```ini
# ntm-client.conf — Windows paths use backslash or forward slash (both work)

server               = 192.168.1.10
port                 = 5555
identity             = C:\ProgramData\ntmclient\client_private.pem
server_cert          = C:\ProgramData\ntmclient\server_cert.pem
send_buffer_bytes    = 524288
```

> Both `C:\path\to\file` and `C:/path/to/file` are accepted.

---

## 7. Windows First Run (Foreground)

Open a **Command Prompt as Administrator** and run:

```cmd
"C:\Program Files\ntm-client\ntm-client.exe" ^
    --config "C:\ProgramData\ntmclient\ntm-client.conf" ^
    --verbose
```

Expected output on the console:

```
ntm-client: loaded config from C:\ProgramData\ntmclient\ntm-client.conf (...)
ntm-client: connecting to 192.168.1.10:5555 (identity=..., ...)
ntm-client: connected to 192.168.1.10:5555 (TLS, session max 6h)
```

- All log output goes to **stderr** (the console window). There is no syslog on Windows.
- Press `Ctrl+C` to stop cleanly.
- The `--daemon` flag is **not supported** on Windows and will print a warning.

### Interface names

On Windows, Npcap enumerates interfaces using internal device paths such as:

```
\Device\NPF_{4A5B6C7D-...}
```

These are logged at startup alongside the friendly name (e.g. `Ethernet`, `Wi-Fi`).
The interface list is fixed at startup; a restart is required if interfaces change.

---

## 8. Running as a Background Service

`ntm-client.exe` does not natively register as a Windows Service. The recommended approach
is **Task Scheduler** with the SYSTEM account.

### Using Task Scheduler (PowerShell, run as Administrator)

```powershell
$action  = New-ScheduledTaskAction `
    -Execute  '"C:\Program Files\ntm-client\ntm-client.exe"' `
    -Argument '--config "C:\ProgramData\ntmclient\ntm-client.conf"'

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit    (New-TimeSpan -Hours 0) `
    -RestartCount          10 `
    -RestartInterval       (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId    "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel  Highest

Register-ScheduledTask `
    -TaskName   "ntm-client" `
    -Action     $action `
    -Trigger    $trigger `
    -Settings   $settings `
    -Principal  $principal `
    -Force
```

Start immediately without rebooting:

```powershell
Start-ScheduledTask -TaskName "ntm-client"
```

Check status:

```powershell
Get-ScheduledTask -TaskName "ntm-client" | Select-Object TaskName, State
```

Remove the task:

```powershell
Unregister-ScheduledTask -TaskName "ntm-client" -Confirm:$false
```

> Log output is written to **stderr**, which Task Scheduler discards by default.
> Redirect to a file by changing the action argument to:
> ```
> --config "C:\ProgramData\ntmclient\ntm-client.conf" >> "C:\ProgramData\ntmclient\ntm-client.log" 2>&1
> ```

---

## 9. Windows Security Hardening Checklist

- [ ] Npcap installed (required for packet capture)
- [ ] `ntm-client.exe` runs as SYSTEM or Administrator
- [ ] TLS configured: `server_cert` or `ca` set (server rejects plain TCP)
- [ ] Ed25519 identity configured: `identity` set and public key in server's `allowed_clients.txt`
- [ ] `client_private.pem` ACL restricts read access to SYSTEM and Administrators only
- [ ] Config directory `C:\ProgramData\ntmclient\` is not readable by standard users
- [ ] Server certificate renewed before expiry if using pinning (redeploy to each client)
- [ ] Task Scheduler task set to restart on failure (handles network unavailability at boot)
- [ ] Npcap kept up to date (security fixes are released regularly)
- [ ] Binary installed in `C:\ProgramData\ntm\bin\` with service account ACLs (required for auto-update)
- [ ] Binary is Authenticode code-signed (required for Windows auto-update)

---

## 10. Troubleshooting (Windows)

**`pcap_findalldevs failed` or no interfaces captured**
- Npcap is not installed, or the process is not running as Administrator.
- Verify Npcap is installed: check **Add/Remove Programs** for "Npcap".
- Run `ntm-client.exe` from an elevated Command Prompt.

**`TLS handshake failed`**
- Server certificate CN/SAN does not match the `server` value.
- Pinned cert (`server_cert`) does not match the server's current certificate.
- Confirm the path in `server_cert` or `ca` is correct and the file is readable by SYSTEM.

**`server rejected authentication`**
- The client public key is not in the server's `allowed_clients.txt`.
- Re-derive the hex public key and add it to the server allowlist.

**`ntm-client: NOTE: ensure identity key is protected via NTFS permissions`**
- Set the ACL on `client_private.pem` as shown in Section 4.

**Client connects but server shows no traffic**
- Run with `--verbose` to confirm sniffers started and interfaces were found.
- Confirm Npcap is installed and the process is running as Administrator.
- Check that the listed interfaces are the ones carrying the traffic you expect.

**`connect() failed (WSA ...)`**
- Server is not running or the port is blocked by Windows Firewall.
- Add an inbound rule on the **server** machine: `netsh advfirewall firewall add rule name="ntm-server" dir=in action=allow protocol=TCP localport=5555`.
- Verify the server is reachable: `Test-NetConnection -ComputerName 192.168.1.10 -Port 5555`.

**The scheduled task starts but exits immediately**
- Enable output redirection in the task action (see Section 8) to capture the error message.
- Run the binary manually from an elevated prompt first to see the error on screen.

**`--daemon` flag has no effect**
- Daemon mode is not supported on Windows. The flag prints a warning and the process
  continues in the foreground. Use Task Scheduler for background operation.

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

# HTTPS API port — must match web_port in server config (default: 8443)
web_port = 8443
```

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
2. Download written to `.exe.pending` in the binary directory (located via `GetModuleFileName`).
3. SHA-256 verification identical to Linux; failure aborts and deletes the pending file.
4. `MoveFile` renames the running binary to `.exe.old`, then renames the pending file to
   `ntm-client.exe`.
5. The client calls `ExitProcess(0)`. Task Scheduler detects the exit and relaunches the
   process within approximately one minute with the new binary.

On startup, any stale `.exe.old` file from a previous update is deleted automatically.

Because the pending file and the running binary are always in the same directory (same
filesystem), the rename operations are atomic and never require a cross-device copy.

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

**Windows — recommended path:** `C:\ProgramData\ntm\bin\ntm-client.exe`

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\ntm\bin" -Force
Copy-Item ntm-client.exe "C:\ProgramData\ntm\bin\ntm-client.exe"
icacls "C:\ProgramData\ntm\bin" /grant "SYSTEM:(OI)(CI)F" /inheritance:r
icacls "C:\ProgramData\ntm\bin" /grant "Administrators:(OI)(CI)F"
```

Update the Task Scheduler task action to reference the new path.

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
    ntm-client-windows-amd64-1.9.0.exe
```

## Troubleshooting auto-update

**Binary not updating**
- Confirm `auto_update=true` is set (default is `false`). Checks run every 23 hours.
- Verify the binary in `update_dir` follows the naming convention exactly:
  `ntm-client-linux-amd64-<version>` or `ntm-client-windows-amd64-<version>.exe`.
- Confirm a manifest scan was run on the server after placing the binary.
- Confirm the binary version in the filename is higher than the client's current version.
- On Windows, verify the binary is Authenticode code-signed.

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
Remove-Item "C:\ProgramData\ntm\bin\ntm-client.exe.old"
```

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
| `ca` | `--ca` | *(none)* | CA bundle to verify server certificate |
| `server_cert` | `--server-cert` | *(none)* | Server cert for SHA-256 fingerprint pinning |
| `send_buffer_bytes` | — | `524288` | Send buffer size in bytes (4096–2097152) |
| `external_ip_url` | — | `http://checkip.amazonaws.com/` | URL used to detect external/WAN IP |
| `external_ip_timeout_ms` | — | `5000` | Timeout for external IP check (500–30000 ms) |
| `reconnect_attempts` | `--reconnect-attempts` | `10` | Max consecutive reconnect failures before exit (1–1000) |
| `reconnect_interval_sec` | `--reconnect-interval` | `60` | Seconds between reconnect attempts (1–3600) |
| `auto_update` | — | `false` | Enable daily binary self-update check (opt-in) |
| `web_port` | — | `8443` | Server HTTPS API port for update checks — same key and default as `web_port` in the server config |
| `verbose` | `--verbose` | `false` | Enable verbose logging |

Precedence: **CLI flags** > **config file** > **built-in defaults**.
