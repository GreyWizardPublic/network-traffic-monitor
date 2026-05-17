#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

// Client↔Server shared protocol constructs (data ingestion + optional Ed25519 auth).

namespace ntm
{

// Default TCP port for client→server data ingestion connections.
inline constexpr std::uint16_t kDefaultPort = 5555;

// Maximum TLS session lifetime (seconds). After this, connection must be closed and renegotiated.
inline constexpr std::uint64_t kMaxSessionSeconds = 6 * 3600; // 6 hours

// Ed25519 authentication v2 (nonce-based). When server uses allowed-keys and client uses identity:
// - Client sends: [1 byte version=2]
// - Server replies: [32 byte nonce]
// - Client sends: [32 byte pubkey][64 byte signature]
// - Signature = Ed25519 sign("NTM-AUTH-v2" + nonce_32bytes, client_private_key).
// - Server replies: [1 byte] 0x00 = OK, 0x01 = auth failed.
inline constexpr unsigned kAuthVersionV2 = 2;
inline constexpr std::size_t kAuthPubkeyLen = 32;
inline constexpr std::size_t kAuthSignatureLen = 64;
inline constexpr std::size_t kAuthNonceLen = 32;
inline constexpr char kAuthSignPrefixV2[] = "NTM-AUTH-v2";
inline constexpr std::size_t kAuthSignPrefixV2Len = sizeof(kAuthSignPrefixV2) - 1;

// Simple line-based data protocol:
// "D iface src_ip dst_ip bytes\n"      — packet metadata (main data stream)
// "A ip_address\n"                     — address announce: one LAN IP per line,
//                                        sent by the client immediately after auth
//                                        so the server can attribute traffic from
//                                        all of the client's interfaces (IPv4 and
//                                        IPv6) to this client's stable ID.
//
// Fields are separated by single spaces, no spaces inside fields.
inline constexpr char kDataLinePrefix[] = "D ";
inline constexpr char kAddrLinePrefix[] = "A ";

// Maximum address-announce lines the server will accept per session.
inline constexpr std::size_t kMaxAnnounceAddressesPerSession = 64;

struct PacketMeta
{
    std::string iface;
    std::string srcIp;
    std::string dstIp;
    std::uint32_t bytes{0};
};

} // namespace ntm

