#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

// Client↔Server shared protocol constructs (data ingestion + optional Ed25519 auth).
// See docs/wire-protocol.md for the authoritative specification.

namespace ntm
{

// Wire protocol version (integer). Bump when any line format, field count, or
// connection-lifecycle rule changes. See docs/wire-protocol.md § 6.
// Lockstep consumers: ntm-server, ntm-client (C++), NTMClient (iOS).
inline constexpr unsigned kWireProtoVersion = 2;

// HTTPS API protocol version (integer). Bump when endpoint schemas change.
// See docs/api-protocol.md § 5 for change classification rules.
// Lockstep consumers: ntm-server, NTMDashboard (iOS), embedded web dashboard.
inline constexpr unsigned kApiVersion = 7;

// Default TCP port — serves both ntm-client data ingestion and the HTTPS
// dashboard when port consolidation is in use (see docs/wire-protocol.md § 2).
inline constexpr std::uint16_t kDefaultPort = 5555;

// TLS ALPN protocol identifiers used for port multiplexing.
// ntm-client advertises kAlpnNtmWire; browsers advertise kAlpnHttp11 (by default).
// The server selects "ntm-wire" > "http/1.1" > "http/1.1" fallback (no-ALPN clients).
inline constexpr char kAlpnNtmWire[] = "ntm-wire";
inline constexpr char kAlpnHttp11[]  = "http/1.1";

// Select the ALPN protocol from the client's wire-format offer list.
// Input: OpenSSL wire format — length-prefixed strings concatenated
//   e.g. "\x08ntm-wire\x08http/1.1" for a client offering both.
// Returns: "ntm-wire" > "http/1.1" (priority order); "http/1.1" as fallback
// for clients that offer nothing recognised (e.g. older browsers with no ALPN).
// Pure function — no OpenSSL dependency; directly unit-testable.
inline std::string selectAlpnFromClientList(const unsigned char *in,
                                             unsigned int         inlen)
{
    // First pass: look for "ntm-wire" (highest priority — data-ingestion client).
    const unsigned char *p   = in;
    const unsigned char *end = in + inlen;
    while (p < end)
    {
        unsigned char len = *p++;
        if (p + len > end) break;
        if (len == 8 && std::memcmp(p, "ntm-wire", 8) == 0)
            return kAlpnNtmWire;
        p += len;
    }
    // Second pass: look for "http/1.1" (dashboard browsers).
    p = in;
    while (p < end)
    {
        unsigned char len = *p++;
        if (p + len > end) break;
        if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0)
            return kAlpnHttp11;
        p += len;
    }
    // Fallback: no recognised protocol in the offer list (e.g. client sent no ALPN).
    return kAlpnHttp11;
}

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

// Ed25519 authentication v3 (nonce + capability exchange).
// Extends v2: after pubkey+sig the client appends a 1-byte capability flags field.
// After result=kAuthResultOk the server appends a 1-byte negotiated capability flags field.
// v2 clients are still accepted by new servers; they get no capability byte and no compression.
inline constexpr unsigned    kAuthVersionV3 = 3;

// Capability bit flags (1 byte).  Sent by client and echoed (masked) by server.
inline constexpr std::uint8_t kCapNone = 0x00; // no optional features
inline constexpr std::uint8_t kCapZlib = 0x01; // bit 0: zlib deflate on the data phase

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

// Parse a D-line body (the part after the "D " prefix) into PacketMeta.
// Format: "{iface} {src_ip} {dst_ip} {bytes}"
// Fields are separated by any run of whitespace (space, tab, CR, LF).
// Returns false if any field is missing, the bytes field is non-numeric,
// bytes > UINT32_MAX, or a label exceeds its length limit.
// maxIfaceLen and maxIpLen default to kMaxIfaceLabelLen / kMaxIpLabelLen when 0.
// Pure function — no I/O, no OpenSSL, directly unit-testable.
inline bool parseDataLine(const std::string &line, PacketMeta &out,
                          std::size_t maxIfaceLen = 0,
                          std::size_t maxIpLen    = 0)
{
    if (line.empty())
        return false;

    const char *p   = line.data();
    const char *end = p + line.size();
    auto isSep = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    auto nextTok = [&](const char *&b, const char *&e) -> bool {
        while (p < end && isSep(*p)) ++p;
        if (p >= end) return false;
        b = p;
        while (p < end && !isSep(*p)) ++p;
        e = p;
        return true;
    };

    const char *ib, *ie, *sb, *se, *db, *de, *bb, *be;
    if (!nextTok(ib, ie) || !nextTok(sb, se) ||
        !nextTok(db, de) || !nextTok(bb, be))
        return false;

    if (maxIfaceLen == 0) maxIfaceLen = kMaxIfaceLabelLen;
    if (maxIpLen    == 0) maxIpLen    = kMaxIpLabelLen;

    const std::size_t ifaceLen = static_cast<std::size_t>(ie - ib);
    const std::size_t srcLen   = static_cast<std::size_t>(se - sb);
    const std::size_t dstLen   = static_cast<std::size_t>(de - db);
    if (ifaceLen > maxIfaceLen || srcLen > maxIpLen || dstLen > maxIpLen)
        return false;

    char *numEnd = nullptr;
    unsigned long val = std::strtoul(bb, &numEnd, 10);
    if (numEnd == bb)         // no digits consumed
        return false;
    if (val > static_cast<unsigned long>(UINT32_MAX))
        return false;

    out.iface.assign(ib, ifaceLen);
    out.srcIp.assign(sb, srcLen);
    out.dstIp.assign(db, dstLen);
    out.bytes = static_cast<std::uint32_t>(val);
    (void)be;
    return true;
}

} // namespace ntm

