# NTM Client — iOS Packet Capture Agent Deployment Guide

Native SwiftUI app for iPhone and iPad that acts as an `ntm-client` wire-protocol
agent. Connects to `ntm-server` over TLS using an Ed25519 key pair and appears in
the server dashboard just like any Linux or Windows ntm-client.

This app is **separate** from NTM Dashboard. NTM Dashboard reads traffic data from
the server; NTM Client sends traffic data to the server.

---

## Requirements

| Requirement | Version |
|---|---|
| iOS / iPadOS | 18.0 or later |
| Xcode | 16.0 or later |
| Swift | 6.0 (strict concurrency) |
| ntm-server | 1.5.0 or later (api_version 3 — client registration endpoint) |
| XcodeGen | Latest (`brew install xcodegen`) |

The server must have `allowed_keys` configured and WebAuthn enabled
(`webauthn_rp_id` set) so the client registration API endpoint is active.

---

## Build

### 1. Generate the Xcode project

```bash
cd ios/NTMClient
xcodegen generate
```

This reads `project.yml` and produces `NTMClient.xcodeproj`.

### 2. Open and build in Xcode

```bash
open NTMClient.xcodeproj
```

Select your target device or simulator, then **Product → Build** (`⌘B`).

### 3. Configure signing

In Xcode, select the **NTMClient** target → **Signing & Capabilities**:

- Set **Team** to your Apple Developer account.
- Bundle ID is `com.ntm.NTMClient`.

---

## First launch — Setup tab

### 1. Configure the server

In the **Setup** tab, fill in:

| Field | Description | Example |
|---|---|---|
| Host | Server hostname | `ntm.example.com` |
| HTTPS port | Port for the HTTPS API (key registration) | `8443` |
| Wire port | Port for the wire-protocol connection | `5555` |
| Device nickname | How this device appears in the dashboard | `Harry's iPhone` |

### 2. Certificate pinning (optional, for self-signed certs)

Tap **Import server certificate (DER)** and select the `.der` file.

Export the server cert in DER format if needed:

```bash
openssl x509 -in /etc/ntm-server/server_cert.pem -outform DER -out server_cert.der
```

### 3. Generate an Ed25519 key pair

Tap **Generate key pair**. The private key is created and stored in the device
Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`). It never leaves
the device.

### 4. Register this device

1. Tap **Sign in with passkey** — authenticates with the server using Face ID /
   Touch ID (the same passkey used for NTM Dashboard).
2. Tap **Register this device** — calls `POST /api/admin/client/register` on the
   server, which adds the device's public key to the server's `allowed_keys` file
   and live in-memory store.

Once registered, the app shows **Key registered on server ✓** and automatically
starts the wire-protocol connection.

---

## Status tab

The **Status** tab shows the live connection state:

| State | Meaning |
|---|---|
| Connected (green) | TCP/TLS connected and authenticated; H heartbeats being sent |
| Connecting (yellow) | TCP/TLS or auth in progress |
| `<error>` (red) | Connection failed; reconnect will be attempted with backoff |
| Not started (grey) | Setup not complete |

The device appears in the ntm-server dashboard under **Client health** once
connected. The client sends a health heartbeat (`H` line) every 30 seconds.

---

## How the wire connection works

After successful setup:

1. The app opens a TLS connection to `<host>:<wire-port>`.
2. Performs Ed25519 authentication:
   - Sends version byte `0x02`
   - Receives a 32-byte nonce from the server
   - Signs `"NTM-AUTH-v2" ‖ nonce` with the device's private key
   - Sends raw public key (32 bytes) + signature (64 bytes)
   - Receives `0x00` (accepted) or `0x01` (rejected)
3. Sends local interface addresses (`X null` then `A <ip>` for each LAN address).
4. Sends a health heartbeat (`H pcap_recv=0 …`) every 30 seconds.
5. Reconnects automatically on failure with exponential backoff (2 s → 4 → … → 60 s).
6. Reconnects before the server's 6-hour session limit.

---

## Server prerequisites

The server must have `allowed_keys` configured:

```ini
allowed_keys = /etc/ntm-server/allowed-clients.keys
```

This file is created automatically on first client registration (the directory
must exist and be writable by the `ntm-server` user).

The registration endpoint (`POST /api/admin/client/register`) is only active when
both `allowed_keys` and `webauthn_rp_id` are set.

---

## Packet capture

Tap **Start capture** on the Status tab to activate the `NEPacketTunnelProvider` extension.
This intercepts all IP traffic on the device and streams D-line observations to ntm-server.

### Requirements

- An Apple Developer account with the **Network Extensions** capability enabled for your App ID.
- The `packet-tunnel-provider` entitlement must be present in both the main app and the
  extension target (already included in the project).

### First use

On first tap iOS displays a system alert asking permission to add a VPN configuration.
Tap **Allow**. This is a local VPN profile — no traffic leaves the device except through
the normal network stack.

### Known limitations

| Limitation | Detail |
|---|---|
| **TCP internet broken while active** | TCP packets are observed (D-lines sent) but not forwarded. HTTP/HTTPS and other TCP-based apps will not work while capture is running. |
| **UDP forwarded (DNS works)** | UDP packets including DNS (port 53) are forwarded through the extension. DNS resolution continues to work. |
| **Custom DNS replaced** | The system DNS servers are overridden with `8.8.8.8` and `1.1.1.1` while capture is active. |
| **IPv6 UDP not forwarded** | IPv6 UDP packets are observed (D-lines) but not forwarded in this release. |
| **Simulator not supported** | Packet tunnel extensions cannot run in the iOS Simulator. Device required. |

### How it works

1. Main app passes the Ed25519 private key and server config to the extension via
   `NETunnelProviderProtocol.providerConfiguration` (encoded as base64).
2. The extension opens its own wire-protocol connection to ntm-server.
3. All IP traffic on the device is routed through the virtual tunnel interface.
4. The extension parses each IP packet and sends a `D utun <src> <dst> <bytes>` line to
   ntm-server, and forwards UDP payloads directly to the destination.
5. While the VPN is active, the main app's wire connection is paused to avoid two
   simultaneous connections from the same Ed25519 key.
6. When the VPN stops, the main app resumes its own wire connection (heartbeats only).

### D-line rate

The server accepts up to 20,000 D-lines per second per connection; excess lines are silently
dropped. At typical household traffic rates this limit is not reached.

---

## Troubleshooting

**Status shows "No key pair generated"**  
Go to Setup and tap **Generate key pair**.

**Status shows "Key not registered on server"**  
Sign in with your passkey in Setup, then tap **Register this device**.

**"Server rejected key"**  
The key is not in the server's allowed-keys list. The registration step may not
have completed. Tap **Register this device** again. If it returns a 404 error,
confirm the server has `allowed_keys` configured.

**"Not authorised — sign in first"**  
The passkey session has expired. Tap **Sign in with passkey** to refresh it,
then retry registration.

**TLS error on wire connection**  
- For CA-signed certs: ensure the full certificate chain is used on the server.
- For self-signed certs: import the server cert DER in Setup.
- Re-import if the server certificate was recently renewed.

**Device does not appear in Client health on the dashboard**  
- Confirm the Status tab shows **Connected**.
- The client sends an H heartbeat every 30 s; it may take up to 30 s to appear.
- Clients with no H line in the last 90 s are marked **stale**.

---

## Version compatibility

Requires ntm-server 1.5.0 or later (api_version 3), which introduced the
`POST /api/admin/client/register` endpoint. Earlier server versions do not
support the iOS client registration flow.
