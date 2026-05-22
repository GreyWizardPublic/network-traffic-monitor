# ntm-client Auto-Update

Covers the automatic binary update mechanism for `ntm-client` on **Linux** and **Windows**.
Auto-update is **not** supported for the iOS client (NTMClient/NTMDashboard); those are
distributed through the App Store.

## Table of Contents

1. [Overview](#1-overview)
2. [Binary naming convention](#2-binary-naming-convention)
3. [Server setup](#3-server-setup)
   - [Create the update directory](#create-the-update-directory)
   - [Place binaries](#place-binaries)
   - [Enable in server config](#enable-in-server-config)
   - [Scan and generate the manifest](#scan-and-generate-the-manifest)
4. [Client setup](#4-client-setup)
5. [How updates are applied](#5-how-updates-are-applied)
   - [Linux](#linux)
   - [Windows](#windows)
6. [Required permissions](#6-required-permissions)
   - [Linux](#linux-1)
   - [Windows](#windows-1)
7. [Admin page workflow](#7-admin-page-workflow)
8. [Security model](#8-security-model)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Overview

When `auto_update=true` is set in the client config, `ntm-client` contacts the server's HTTPS
API once every 23 hours to check whether a newer binary is available for its platform. If one
is found, the client downloads it, verifies its SHA-256 digest, and applies it without
requiring operator intervention on the client machine.

**What is included:**

- Linux (`ntm-client`, amd64)
- Windows (`ntm-client.exe`, amd64)

**What is excluded:**

- iOS NTMClient — distributed via the App Store
- iOS NTMDashboard — distributed via the App Store
- `ntm-server` — server binary updates are not managed by this mechanism

Auto-update is **opt-in** and **off by default**. The feature only activates when
`auto_update=true` is present in the client config. If `update_dir` is not configured on the
server, the `/api/update/*` endpoints are not registered and the feature remains inactive
server-side regardless of client config.

---

## 2. Binary naming convention

Binaries placed in `update_dir` must follow this exact naming scheme:

| Platform | Filename pattern | Example |
|---|---|---|
| Linux (amd64) | `ntm-client-linux-amd64-<version>` | `ntm-client-linux-amd64-1.9.0` |
| Windows (amd64) | `ntm-client-windows-amd64-<version>.exe` | `ntm-client-windows-amd64-1.9.0.exe` |

Where `<version>` matches the `MAJOR.MINOR.PATCH` version string embedded in the binary.
The server parses the version from the filename and includes it in the manifest. Files that
do not match the pattern are ignored during scanning.

---

## 3. Server setup

### Create the update directory

```bash
sudo mkdir -p /var/lib/ntm-server/updates
sudo chown ntm-server:ntm-server /var/lib/ntm-server/updates
sudo chmod 750 /var/lib/ntm-server/updates
```

### Place binaries

Copy the compiled binaries into the update directory using the naming convention above:

```bash
sudo cp build-linux/ntm-client \
    /var/lib/ntm-server/updates/ntm-client-linux-amd64-1.9.0

sudo cp build-windows/ntm-client.exe \
    /var/lib/ntm-server/updates/ntm-client-windows-amd64-1.9.0.exe
```

Only one binary per platform is served at a time. If multiple versions for the same platform
are present, the server serves the highest version number. Older versions can be left in the
directory or removed — they are not served but do no harm.

### Enable in server config

Add `update_dir` to `/etc/ntm-server/ntm-server.conf`:

```ini
update_dir = /var/lib/ntm-server/updates
```

The server registers the `/api/update/*` endpoints only when `update_dir` is non-empty.
Restart the server after adding this key.

### Scan and generate the manifest

After placing or replacing binaries, trigger a manifest scan so the server knows what is
available. Use either:

**Admin page:** navigate to the admin section of the web dashboard and click
**"Scan & Refresh Manifest"**.

**curl (admin session required):**

```bash
curl -sk -X POST \
  -H "Cookie: <admin-session-cookie>" \
  https://localhost:8443/api/admin/update/scan
```

The server writes `manifest.json` to `update_dir`. Clients see the new version on their next
23-hour check cycle, or immediately after an operator triggers a force update.

---

## 4. Client setup

Add the following keys to the client's config file:

```ini
# Enable automatic binary updates (default: false — must opt in)
auto_update = true

# HTTPS API port — same key and default as web_port in the server config (default: 8443)
# Only set this if the server uses a non-default web_port.
web_port = 8443
```

The client uses the same `server` and `server_cert`/`ca` settings already configured for
TLS. No additional certificate configuration is needed.

After changing the config, restart the client. The first update check runs approximately 23
hours after the client starts.

---

## 5. How updates are applied

### Linux

1. The client sends `GET /api/update/check?platform=linux&version=<ver>&pubkey=<hex>` to
   the server's HTTPS API.
2. If the server responds with `{"available": true, ...}`, the client downloads the binary
   via `GET /api/update/download?platform=linux&pubkey=<hex>`.
3. The binary is written to a `.pending` file in the same directory as the running binary
   (located via `/proc/self/exe`).
4. The SHA-256 digest of the downloaded file is verified against the value in the server
   response. If verification fails the `.pending` file is deleted and the update is aborted.
5. The pending binary is made executable (`chmod +x`).
6. An atomic `rename(pending, binary)` replaces the running binary on disk.
7. The client calls `execv` on itself, hot-reloading the new binary in place. The process ID
   is preserved; systemd does not need to restart the unit.

**On startup:** if a stale `.pending` file exists (left by a previous interrupted update),
the client deletes it before beginning normal operation.

### Windows

1. The client sends `GET /api/update/check?platform=windows&version=<ver>&pubkey=<hex>` to
   the server's HTTPS API.
2. If the server responds with `{"available": true, ...}`, the client downloads the binary
   via `GET /api/update/download?platform=windows&pubkey=<hex>`.
3. The binary is written to a `.exe.pending` file in the same directory as the running binary
   (located via `GetModuleFileName`).
4. SHA-256 verification is performed as on Linux; failure aborts the update.
5. `MoveFile` renames the currently running binary to `ntm-client.exe.old`.
6. `MoveFile` renames the pending file to `ntm-client.exe`.
7. The client calls `ExitProcess(0)`. Task Scheduler detects the exit and restarts the
   process within approximately one minute, launching the new binary.

**On startup:** if a stale `.exe.old` file exists (left by a previous successful update),
the client deletes it before beginning normal operation.

> The pending file and the running binary are always on the same filesystem (same directory),
> so the `rename`/`MoveFile` operations are atomic and never require a cross-device copy.

---

## 6. Required permissions

### Linux

The client binary must be installed in a directory owned by the service user so that the
atomic rename in step 6 can succeed without elevated privileges at update time.

Recommended install path: `/opt/ntm/bin/ntm-client`

```bash
sudo mkdir -p /opt/ntm/bin
sudo install -m 755 build-linux/ntm-client /opt/ntm/bin/ntm-client
sudo chown ntmclient:ntmclient /opt/ntm/bin/ntm-client /opt/ntm/bin
```

The `ntmclient` service user (created in `CLIENT_DEPLOYMENT.md`, Section 9) must own both
the binary file and the `/opt/ntm/bin/` directory. The service runs without `CAP_DAC_OVERRIDE`
or `CAP_FOWNER` — if the directory is owned by root, the rename will fail with `EACCES`.

### Windows

The binary must be installed in a directory where the service account has write access so
that the `MoveFile` calls in steps 5 and 6 can succeed.

Recommended install path: `C:\ProgramData\ntm\bin\ntm-client.exe`

```powershell
# Create the directory
New-Item -ItemType Directory -Path "C:\ProgramData\ntm\bin" -Force

# Copy the binary
Copy-Item ntm-client.exe "C:\ProgramData\ntm\bin\ntm-client.exe"

# Grant the service account (SYSTEM) full control of the bin directory
icacls "C:\ProgramData\ntm\bin" /grant "SYSTEM:(OI)(CI)F" /inheritance:r
icacls "C:\ProgramData\ntm\bin" /grant "Administrators:(OI)(CI)F"
```

Update the Task Scheduler action to point to `C:\ProgramData\ntm\bin\ntm-client.exe`.

**Windows code-signing requirement:** Windows Defender and SmartScreen will block execution
of unsigned binaries downloaded from the network. All Windows binaries distributed via
auto-update must be **Authenticode code-signed** with a trusted certificate. Unsigned binaries
will be quarantined or blocked before the client can apply them.

Sign the binary before placing it in `update_dir`:

```powershell
# Sign with a code-signing certificate (signtool from Windows SDK)
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
    /n "Your Organization Name" `
    ntm-client-windows-amd64-1.9.0.exe
```

---

## 7. Admin page workflow

The web dashboard admin section provides three controls for managing auto-update:

**Scan & Refresh Manifest**
Rescans `update_dir` and regenerates `manifest.json`. Use this after placing new binaries in
the update directory. The button is equivalent to `POST /api/admin/update/scan`.

**Client health table**
The admin page shows a row per connected client. The version column displays the client's
reported version. Rows are highlighted in **amber** when a newer binary is available for that
client's platform, making it easy to identify which clients are pending an update.

**Force Update (per client)**
Each client row has a "Force Update" button. Clicking it sets a one-shot force flag for that
client (identified by its Ed25519 public key hex). On the client's next update check the
server responds with `{"available": true, "force": true}` regardless of the client's current
version. This can be used to push an urgent update or to re-apply a binary to a client that
has been stuck.

The force flag is consumed on first use — subsequent checks return to normal version
comparison behavior.

The force flag can also be set via the API (admin session required):

```bash
curl -sk -X POST \
  -H "Cookie: <admin-session-cookie>" \
  -H "Content-Type: application/json" \
  -d '{"client": "<64-char-pubkey-hex>"}' \
  https://localhost:8443/api/admin/update/force
```

---

## 8. Security model

**Transport security:** update checks and binary downloads use the same TLS connection
configured for the HTTPS API (`server_cert` / `ca`). The server rejects plain HTTP.

**Integrity verification:** the server computes the SHA-256 digest of each binary at scan
time and records it in `manifest.json`. The client verifies the downloaded binary against
this digest before writing the pending file. A digest mismatch causes the update to be
aborted and the pending file to be deleted.

**Authentication:** the update check endpoint requires the client's Ed25519 public key as the
`pubkey` query parameter. The server validates that the key is present in `allowed_clients.txt`
before returning update information or serving a binary. Anonymous downloads are rejected.

**Code signing (Windows only):** Authenticode signing provides an additional trust anchor
independent of the TLS channel. A compromised server that serves a malicious binary would
still be blocked by Defender/SmartScreen before the binary can execute.

**What the security model does not cover:**

- If the server's TLS private key is compromised, an attacker controlling the network could
  serve arbitrary binaries. Protect `server_key.pem` with strict file permissions and rotate
  it periodically.
- SHA-256 verification confirms the downloaded file matches what the server advertised, but
  does not verify the server's intent to serve a legitimate binary. The operator is
  responsible for placing only trusted binaries in `update_dir`.

---

## 9. Troubleshooting

**Client is not checking for updates**
- Confirm `auto_update=true` is present in the client config (it defaults to `false`).
- Checks run on a 23-hour cycle; the first check occurs 23 hours after startup.
- Run with `--verbose` to see update check log lines.

**"binary not updating" — check succeeds but no update applied**
- Verify the binary in `update_dir` follows the naming convention exactly (see Section 2).
- Confirm `POST /api/admin/update/scan` was called after placing the binary.
- Check that the version in the filename is higher than the client's current version.
- On Windows, confirm the binary is Authenticode code-signed; Defender may be blocking it.

**Pending file not cleaned up**
- Linux: a `.pending` file in the binary directory indicates an interrupted update. The
  client deletes this automatically on next startup. It can be removed manually if the
  client will not restart soon: `rm /opt/ntm/bin/ntm-client.pending`
- Windows: an `.exe.old` file indicates a completed update where the old binary was not yet
  deleted. The client removes it on next startup, or it can be deleted manually.

**"rename failed: Permission denied" (Linux)**
- The service user does not own the binary directory. The directory must be owned by
  `ntmclient` (or whichever user the service runs as). See Section 6 for the correct
  `chown` command.

**"MoveFile failed" (Windows)**
- The SYSTEM account does not have write permission on `C:\ProgramData\ntm\bin\`.
  Re-apply the `icacls` commands from Section 6.

**SHA-256 verification failed**
- The downloaded binary is corrupt or was modified in transit. The pending file is
  automatically deleted. Check network stability and retry; if the problem persists,
  re-scan the manifest on the server to confirm the recorded digest matches the file.

**Force update flag not clearing**
- The force flag is consumed on first successful check response. If the client was offline
  when the flag was set, it will be delivered on the next check. If the client continues to
  show as outdated in the admin page after an update, confirm the client restarted
  successfully with the new binary (check `--version` output or verbose logs).

**Update check returns 404**
- `update_dir` is not configured in the server config, or the server was not restarted after
  adding it. The `/api/update/*` endpoints are only registered when `update_dir` is non-empty.
