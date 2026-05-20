# NTM Dashboard — iOS App Deployment Guide

Native SwiftUI monitoring app for iPhone and iPad. Displays live traffic data
from `ntm-server` using FIDO2 passkey authentication (Face ID / Touch ID).

---

## Requirements

| Requirement | Version |
|---|---|
| iOS / iPadOS | 18.0 or later |
| Xcode | 16.0 or later |
| Swift | 6.0 (strict concurrency) |
| ntm-server | 1.3.0 or later (WebAuthn mode required) |
| XcodeGen | Latest (`brew install xcodegen`) |

The app requires **WebAuthn mode** on the server — set `webauthn_rp_id` in the
server config. The server must be accessible at a valid HTTPS domain (e.g. via
Cloudflare Tunnel). Bare IP addresses cannot be used with passkeys.

---

## Build

### 1. Install XcodeGen

```bash
brew install xcodegen
```

### 2. Generate the Xcode project

```bash
cd ios/NTMDashboard
xcodegen generate
```

This reads `project.yml` and produces `NTMDashboard.xcodeproj`.

### 3. Open and build in Xcode

```bash
open NTMDashboard.xcodeproj
```

Select your target device or simulator, then **Product → Build** (`⌘B`).

### 4. Configure signing

In Xcode, select the **NTMDashboard** target → **Signing & Capabilities**:

- Set **Team** to your Apple Developer account.
- The Bundle ID is `com.ntm.NTMDashboard` — change it if needed to match your
  provisioning profile.

> **Passkeys require an associated domain.** The server's `webauthn_rp_id` must
> match the domain configured in the AASA entitlement. If you changed the
> bundle ID or domain, update both `webauthn_ios_app_id` in the server config
> and the Associated Domains entitlement in Xcode.

---

## Server prerequisites

Before using the iOS app, the server must be running in WebAuthn mode with the
iOS app site association configured.

### 1. Server config (relevant keys)

```ini
webauthn_rp_id             = ntm.example.com
webauthn_rp_name           = NTM Dashboard
webauthn_credentials_file  = /etc/ntm-server/webauthn-credentials.json
webauthn_admin_cred_file   = /etc/ntm-server/webauthn-admin.json
webauthn_ios_app_id        = TEAMID1234.com.ntm.NTMDashboard
```

`webauthn_ios_app_id` is your Apple Team ID followed by a dot and the bundle ID
(e.g. `A1B2C3D4E5.com.ntm.NTMDashboard`). Find your Team ID in
[developer.apple.com](https://developer.apple.com) under Membership.

This causes the server to serve an Apple App Site Association (AASA) file at
`/.well-known/apple-app-site-association`, which iOS requires to bind passkeys
to your domain.

### 2. First-run passkey registration

If no passkey is registered yet, follow the bootstrap flow described in
[SERVER_DEPLOYMENT.md § Setting up WebAuthn passkeys](SERVER_DEPLOYMENT.md#11-web-dashboard-access)
using a browser on your Mac or PC. Once at least one passkey is registered on the
domain, you can register additional devices from the iOS app itself.

---

## First launch and configuration

### 1. Configure the server connection

On first launch the app shows "Not configured — add server details in Settings".
Tap the **gear icon** (Settings) and fill in:

| Setting | Description | Example |
|---|---|---|
| Host | Server hostname (no `https://`) | `ntm.example.com` |
| Port | HTTPS port | `8443` |
| Polling interval | How often to refresh data (seconds) | `5` |
| Pinned certificate | DER-encoded server cert (optional — see below) | — |

Tap **Save**.

### 2. Certificate pinning (optional, for self-signed certs)

If your server uses a self-signed TLS certificate, the iOS app will refuse the
connection by default. You can pin the server certificate instead of using a
CA-signed cert:

1. Export the server certificate in DER format:

   ```bash
   openssl x509 -in /etc/ntm-server/server_cert.pem -outform DER \
     -out server_cert.der
   ```

2. Transfer `server_cert.der` to your iPhone (AirDrop, Files app, or any method).

3. In the NTM Dashboard app → **Settings → Import Certificate** — select the
   `.der` file. The app stores it and uses it for all future connections to this server.

> If you regenerate the server certificate you must re-import the new DER file
> on each iOS device, otherwise connections will fail.

### 3. Sign in with a passkey

After configuring the server, tap **Sign In**. The app calls `/auth/login/begin`
on the server and presents the system passkey sheet (Face ID or Touch ID
authentication). Authenticate and the session token is stored in Keychain.

If you do not have a passkey registered for this domain yet, use **Register this
device** instead (see below).

### 4. Register this device (additional devices)

If you are adding a second iOS device (or any device after the first):

1. Tap **Register this device** on the login screen.
2. Enter the **admin password** (the one originally used to bootstrap the server).
3. The app derives a PBKDF2 proof locally (the password is never sent to the server)
   and completes WebAuthn registration, storing the new passkey on the device's
   Secure Enclave.

---

## Dashboard features

After signing in, the main screen shows a live snapshot of traffic data,
auto-refreshed at the configured polling interval. Pull down to force an
immediate refresh.

| Section | Description |
|---|---|
| **Interfaces** | Per-client, per-interface packet and byte totals over the aggregation window |
| **Entity flows** | Top (source ASN, destination ASN) pairs sorted by bytes |
| **Client health** | One row per connected ntm-client: pcap stats, drop rates, staleness |

The connection bar at the top shows the server host and the time of the last
successful data fetch.

---

## Signing out

Sign out via **Settings → Sign Out**. This calls `/auth/logout` on the server
(invalidating the session token) and clears the Keychain token on the device.
The passkey credential remains registered on the server — sign in again with
Face ID / Touch ID to re-establish a session.

---

## Troubleshooting

**"Server not configured — add host in Settings"**  
Open Settings and enter the server host and port.

**"Cannot reach server"**  
- Confirm `ntm-server` is running and the Cloudflare Tunnel (or reverse proxy) is active.  
- Verify the host and port in Settings match the server config.  
- If using a self-signed cert, import the DER certificate in Settings.

**Passkey sheet does not appear / "No passkeys available"**  
- The device does not have a passkey registered for this domain. Use **Register this device**.  
- Confirm `webauthn_ios_app_id` in the server config matches your Team ID and bundle ID exactly.  
- Confirm the server is serving `/.well-known/apple-app-site-association` — open that URL in Safari to verify.

**"Admin proof failed" during registration**  
The admin password entered is incorrect. Use the same password that was used to bootstrap the server (before migration). If migration has already run and the plaintext file was erased, the password itself has not changed — only its storage format has.

**TLS error / certificate validation failed**  
- For CA-signed certs: confirm the chain is complete (`fullchain.pem`, not just the leaf).  
- For self-signed certs: import the server cert DER in Settings (see Section above).  
- Re-import if the server certificate was recently renewed.

**Data shows stale values**  
Check the connection bar for the last-updated time. Pull to refresh. If the
server shows no new data, check `ntm-client` health in the **Client health**
section — stale clients (no data in > 90 seconds) are flagged.

---

## Version compatibility

The iOS app uses the server's HTTPS API (v2). See
[docs/api-protocol.md](docs/api-protocol.md) for the full API specification and
the client behaviour rules for `api_version` mismatches.

The minimum compatible server version is **ntm 1.3.0** (which introduced
`api_version: 2` and all WebAuthn endpoints). Earlier server versions are not
supported by this app.
