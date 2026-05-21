# Network Traffic Monitor

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

A self-hosted, privacy-first network traffic aggregation system. Packet capture agents
run on your devices, send metadata only to a central server, and the traffic is
visualised in a browser or native iOS app — nothing leaves your own infrastructure.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Your infrastructure                     │
│                                                             │
│  ┌──────────────┐   Wire protocol    ┌──────────────────┐  │
│  │  ntm-client  │ ─────────────────► │                  │  │
│  │ (Linux / Win)│   TCP/TLS + Ed25519│   ntm-server     │  │
│  └──────────────┘                    │   (aggregation + │  │
│                                      │    HTTPS API)    │  │
│  ┌──────────────┐                    │                  │  │
│  │  ntm-client  │ ─────────────────► │                  │  │
│  │  (another    │                    └────────┬─────────┘  │
│  │   machine)   │                             │            │
│  └──────────────┘                             │ HTTPS API  │
│                                               │            │
│                          ┌────────────────────┼──────────┐ │
│                          │  Dashboard clients │          │ │
│                          │                    ▼          │ │
│                          │  ┌──────────────────────────┐ │ │
│                          │  │   Web browser (built-in) │ │ │
│                          │  └──────────────────────────┘ │ │
│                          │  ┌──────────────────────────┐ │ │
│                          │  │  NTM Dashboard (iOS app) │ │ │
│                          │  └──────────────────────────┘ │ │
│                          └───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### ntm-server

The central aggregation engine. Accepts connections from any number of `ntm-client`
instances, aggregates packet metadata into per-interface, per-flow, and per-entity
(ASN) totals over a configurable rolling window, and serves the results via an
HTTPS REST API.

Also ships a built-in web dashboard so any browser can display live traffic data
without installing separate software.

**Key properties:**
- TLS and Ed25519 client authentication are both mandatory
- WebAuthn passkey authentication for the dashboard (FIDO2 — Face ID, Touch ID, hardware key)
- LAN-only filter in legacy mode; session-based auth in WebAuthn mode
- IP → ASN/country resolution using CC0-licensed iptoasn.com data (no MaxMind account needed)
- Runs on Linux; written in C++17

→ **[Server deployment guide](SERVER_DEPLOYMENT.md)**

---

### ntm-client

Lightweight packet capture agent. Runs on each monitored device, sniffs all
IPv4/IPv6 traffic on every interface, and streams metadata (interface name,
source IP, destination IP, byte count) to `ntm-server` over an authenticated
TLS connection.

**Key properties:**
- No GUI; designed to run as a daemon or background service
- Sends only metadata — no payload, no ports, no hostnames
- Ed25519 identity key per client — each agent has a stable, verifiable identity
- Supports Linux (libpcap, RTNETLINK change detection) and Windows (Npcap, NotifyIpInterfaceChange)
- Automatically re-announces its external IP and LAN addresses on network changes

→ **[Client deployment guide](CLIENT_DEPLOYMENT.md)**

---

### NTM Dashboard — iOS app

Native SwiftUI monitoring app for iPhone and iPad. Authenticates with the server
using a FIDO2 passkey (Face ID / Touch ID) and displays the same traffic data as
the web dashboard: interface totals, entity flows, LAN device detail, and client
health.

**Key properties:**
- iOS 18+ / Xcode 16+; Swift 6 strict concurrency
- Passkey authentication via `ASAuthorizationController` — no password ever sent
- Session Bearer token stored in Keychain
- Optional TLS certificate pinning for self-signed server certs
- Configurable polling interval; pull-to-refresh
- Requires WebAuthn mode on the server (`webauthn_rp_id` set)

→ **[iOS Dashboard deployment guide](IOS_DEPLOYMENT.md)**

---

### NTM Client — iOS packet capture agent

Native SwiftUI app that acts as a wire-protocol client on iPhone and iPad.
Connects to `ntm-server` over TLS using an Ed25519 key pair and streams
traffic observations (the same protocol as `ntm-client` on Linux/Windows).

**Key properties:**
- iOS 18+ / Xcode 16+; Swift 6 strict concurrency
- Ed25519 key pair generated and stored in Keychain; registered on server via the HTTPS API
- Wire-protocol TCP/TLS connection to ntm-server port 5555
- Appears in the server dashboard's **Client health** section
- Self-healing: automatic reconnect with exponential backoff

→ **[iOS Client deployment guide](IOS_CLIENT_DEPLOYMENT.md)**

---

### Web browser dashboard (built-in)

`ntm-server` embeds a self-contained HTML/JS dashboard served directly over HTTPS.
No separate installation or build step required — open the server URL in any browser.

- **WebAuthn mode:** `https://your.domain.com` (Cloudflare Tunnel or reverse proxy)
- **Legacy LAN mode:** `https://<server-ip>:8443`

---

## Protocols

Both protocols are independently versioned and documented. Components can evolve at
different speeds as long as they stay within their supported version range.

| Protocol | Parties | Transport | Document |
|---|---|---|---|
| **Wire protocol** | ntm-client → ntm-server | TCP/TLS + Ed25519 | [docs/wire-protocol.md](docs/wire-protocol.md) |
| **API protocol** | Browser / iOS app → ntm-server | HTTPS REST + WebAuthn | [docs/api-protocol.md](docs/api-protocol.md) |

### Current versions

| | Version | Introduced in |
|---|---|---|
| Wire protocol | see `kWireProtoVersion` in source | — |
| API protocol | 2 | ntm 1.3.0 |
| Software | see `src/version.hpp` | — |

---

## Quick Build

**Server + Linux client:**

```bash
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release .
cmake --build build-linux -j$(nproc)
# produces: build-linux/ntm-server  build-linux/ntm-client
```

**Windows client** (cross-compile from Linux with MinGW-w64 and Npcap SDK):

```bash
cmake -B build-windows \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
  -DNPCAP_SDK=/opt/npcap-sdk \
  -DCMAKE_BUILD_TYPE=Release .
cmake --build build-windows -j$(nproc)
# produces: build-windows/ntm-client.exe
```

**iOS app:** requires macOS with Xcode 16+ and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```bash
cd ios/NTMDashboard
xcodegen generate
open NTMDashboard.xcodeproj
```

See the deployment guides below for full production setup including TLS,
authentication, and service configuration.

---

## Deployment Guides

| Guide | Description |
|---|---|
| [SERVER_DEPLOYMENT.md](SERVER_DEPLOYMENT.md) | Full server setup: TLS, Ed25519, WebAuthn, systemd, hardening checklist |
| [CLIENT_DEPLOYMENT.md](CLIENT_DEPLOYMENT.md) | Client setup for Linux (systemd) and Windows (Task Scheduler) |
| [IOS_DEPLOYMENT.md](IOS_DEPLOYMENT.md) | NTM Dashboard (iOS): build, passkey registration, certificate pinning |
| [IOS_CLIENT_DEPLOYMENT.md](IOS_CLIENT_DEPLOYMENT.md) | NTM Client (iOS): build, key registration, wire-protocol agent |
| [docs/wire-protocol.md](docs/wire-protocol.md) | Wire protocol specification (ntm-client ↔ ntm-server) |
| [docs/api-protocol.md](docs/api-protocol.md) | API protocol specification (dashboard clients ↔ ntm-server) |

---

## Security Model

| Boundary | Mechanism |
|---|---|
| Client → server data ingestion | Mutual TLS + Ed25519 key authentication (both mandatory) |
| Browser → dashboard | WebAuthn passkey session (recommended) or LAN-only HTTPS (no auth) |
| iOS → dashboard | WebAuthn passkey (Face ID / Touch ID); session token stored in Keychain |
| Data in transit | TLS 1.2+ on all paths |
| Data at rest | Traffic statistics in memory only; WebAuthn credentials and IP→ASN database on disk |

> **Do not expose ntm-server directly to the internet without WebAuthn enabled.**
> The LAN-only filter is bypassed when requests arrive via localhost (e.g. a tunnel),
> so always pair a tunnel with WebAuthn authentication.
>
> See [SERVER_DEPLOYMENT.md § Security hardening checklist](SERVER_DEPLOYMENT.md#13-security-hardening-checklist).

---

## License

Source code: GPL-3.0-or-later — see [`LICENSE`](LICENSE).  
Third-party libraries and data sources: see [`LICENSES.md`](LICENSES.md).
