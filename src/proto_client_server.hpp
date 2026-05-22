#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

// Client↔Server shared protocol constructs (data ingestion + optional Ed25519 auth).
// See docs/wire-protocol.md for the authoritative specification.

namespace ntm
{

// Wire protocol version (integer). Bump when any line format, field count, or
// connection-lifecycle rule changes. See docs/wire-protocol.md § 6.
// Lockstep consumers: ntm-server, ntm-client (C++), NTMClient (iOS).
inline constexpr unsigned kWireProtoVersion = 1;

// HTTPS API protocol version (integer). Bump when endpoint schemas change.
// See docs/api-protocol.md § 5 for change classification rules.
// Lockstep consumers: ntm-server, NTMDashboard (iOS), embedded web dashboard.
inline constexpr unsigned kApiVersion = 6;

// Default TCP port for client→server data ingestion connections.
inline constexpr std::uint16_t kDefaultPort = 5555;

// Hardcoded port for the legacy App Store review demo server (port 12345).
// The iOS client no longer uses this port — demo access now goes through
// POST /api/demo/begin on the main web server port.
// This constant is kept for the server-side legacy demo thread only.
inline constexpr std::uint16_t kDemoPort = 12345;

// Demo session length in seconds. After this the server resets and allows a
// new demo session to begin (so multiple App Store reviewers can use it).
inline constexpr std::int64_t kDemoSessionSec = 900; // 15 minutes

// Maximum TLS session lifetime (seconds). After this the client must reconnect.
inline constexpr std::uint64_t kMaxSessionSeconds = 6 * 3600; // 6 hours

// Ed25519 authentication v2 (nonce-based). See docs/wire-protocol.md § 4.
// Handshake: client→[1B version] server→[32B nonce] client→[32B pubkey|64B sig]
//            server→[1B result: kAuthResultOk or kAuthResultReject]
// Signature input: kAuthSignPrefixV2 (11 bytes, no NUL) || nonce (32 bytes).
inline constexpr unsigned    kAuthVersionV2       = 2;
inline constexpr std::uint8_t kAuthResultOk       = 0x00; // server→client: accepted
inline constexpr std::uint8_t kAuthResultReject   = 0x01; // server→client: rejected
inline constexpr std::size_t kAuthPubkeyLen       = 32;
inline constexpr std::size_t kAuthSignatureLen    = 64;
inline constexpr std::size_t kAuthNonceLen        = 32;
inline constexpr char kAuthSignPrefixV2[]         = "NTM-AUTH-v2";
inline constexpr std::size_t kAuthSignPrefixV2Len = sizeof(kAuthSignPrefixV2) - 1;

// Data-phase line prefixes. See docs/wire-protocol.md § 5.2.
// All lines are newline-terminated UTF-8; fields separated by single spaces.
inline constexpr char kDataLinePrefix[]   = "D "; // D {iface} {src_ip} {dst_ip} {bytes}
inline constexpr char kHealthLinePrefix[] = "H "; // H key=val key=val …  (every kHealthIntervalSec)
inline constexpr char kExtIPLinePrefix[]  = "X "; // X {ipv4|ipv6|null}  (before A lines)
inline constexpr char kAddrLinePrefix[]   = "A "; // A {lan_ip}          (after X line)
inline constexpr char kExtIPNull[]        = "null"; // X-line sentinel: WAN IP unreachable

// Field length limits enforced by the server on D/A/X lines.
inline constexpr std::size_t kMaxIfaceLabelLen = 64; // iface field in D-lines
inline constexpr std::size_t kMaxIpLabelLen    = 50; // src/dst/ip fields in D/A/X lines

// Maximum A-line addresses the server accepts per announce round.
inline constexpr std::size_t kMaxAnnounceAddressesPerSession = 64;

// Minimum seconds between accepted X-lines per connection (server-enforced rate limit).
inline constexpr unsigned kAnnounceRateLimitSec = 30;

// Client sends one H-line every kHealthIntervalSec seconds.
// Server marks a client stale after 3× this interval without a report.
inline constexpr unsigned kHealthIntervalSec = 30;

struct PacketMeta
{
    std::string iface;
    std::string srcIp;
    std::string dstIp;
    std::uint32_t bytes{0};
};

} // namespace ntm

