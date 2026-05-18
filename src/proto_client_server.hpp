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
// "X {ip|null}\n"                      — external (WAN) IP announce: sent once per
//                                        announce round, BEFORE all A lines. ip is
//                                        the client's public internet-facing IP as
//                                        seen by an external check service, or the
//                                        literal "null" when unreachable. Each X line
//                                        atomically resets the client's registry state
//                                        on the server (old LAN IPs discarded).
//                                        Clients sharing the same external IP are
//                                        considered on the same physical LAN.
// "A ip_address\n"                     — LAN address announce: one line per interface
//                                        address, sent after the X line. Allows the
//                                        server to attribute traffic from all of the
//                                        client's interfaces to this client's stable ID.
//
// Clients re-send X + A lines on any network change and every 6 hours.
// Fields are separated by single spaces, no spaces inside fields.
inline constexpr char kExtIPLinePrefix[]    = "X ";
inline constexpr char kExtIPNull[]         = "null";   // sentinel: external IP unreachable
inline constexpr char kDataLinePrefix[]    = "D ";
inline constexpr char kAddrLinePrefix[]    = "A ";
// "H pcap_recv=N pcap_drop=N buf_drop=N\n" — cumulative health stats for the current session.
// Sent by the client every 30 s. Server stores the latest values per client; no accumulation.
inline constexpr char kHealthLinePrefix[]  = "H ";

// Maximum address-announce lines the server will accept per announce round.
inline constexpr std::size_t kMaxAnnounceAddressesPerSession = 64;

struct PacketMeta
{
    std::string iface;
    std::string srcIp;
    std::string dstIp;
    std::uint32_t bytes{0};
};

} // namespace ntm

