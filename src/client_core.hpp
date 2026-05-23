#pragma once

#include "proto_client_server.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <unordered_set>

// Cross-platform constants, IP structs, LAN helpers, TLS helpers, Ed25519 auth.
// No platform headers here — Linux/Windows specifics live in client_platform.hpp.

namespace ntm
{

// ---------------------------------------------------------------------------
// Wire-format IP header structs (packed for direct overlay on packet bytes)
// ---------------------------------------------------------------------------

struct ipv4_header
{
    std::uint8_t  version_ihl;
    std::uint8_t  tos;
    std::uint16_t total_length;
    std::uint16_t id;
    std::uint16_t frag_off;
    std::uint8_t  ttl;
    std::uint8_t  protocol;
    std::uint16_t checksum;
    std::uint32_t src_addr;
    std::uint32_t dst_addr;
};

struct ipv6_header
{
    std::uint32_t ver_tc_fl;
    std::uint16_t payload_len;
    std::uint8_t  next_header;
    std::uint8_t  hop_limit;
    std::uint8_t  src_addr[16];
    std::uint8_t  dst_addr[16];
};

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxIOBytes             = 2 * 1024 * 1024;
inline constexpr std::size_t kSendBatchSize          = 8192;
inline constexpr unsigned    kSenderWakeMs           = 5;
inline constexpr std::size_t kSendBufferDefaultBytes = 512 * 1024;
inline constexpr std::size_t kSendBufferMinBytes     = 4096;
inline constexpr std::size_t kMaxConfigLineLen       = 8192;
inline constexpr std::size_t kMaxConfigValueLen      = 2048;

// Flow aggregation defaults — these match AdaptiveInterval::Config defaults.
inline constexpr std::uint32_t kAggTargetLinesPerSec = 500;
inline constexpr std::uint32_t kAggMinIntervalMs     = 100;
inline constexpr std::uint32_t kAggMaxIntervalMs     = 5000;
inline constexpr std::uint32_t kAggMaxFlows          = 10000;

// ---------------------------------------------------------------------------
// LAN address classification (pure IP arithmetic — no syscalls)
// ---------------------------------------------------------------------------

bool isLanAddrV4(std::uint32_t networkOrderAddr);   // takes s_addr / in_addr.s_addr
bool isLanAddrV6(const std::uint8_t addr[16]);       // takes in6_addr.s6_addr

// ---------------------------------------------------------------------------
// TLS helpers (OpenSSL — cross-platform)
// ---------------------------------------------------------------------------

SSL_CTX *createClientTLSContext(const std::string &caPath,
                                const std::string &serverCertPath);

X509    *loadPemCert(const std::string &path);
bool     sha256Fingerprint(const X509 *cert, unsigned char out[32]);

// Verify hostname/IP match and optional cert pinning against pinnedServerCertPath.
bool verifyServerIdentityAndPin(SSL *ssl,
                                const std::string &host,
                                const std::string &pinnedServerCertPath,
                                bool verbose, bool isDaemon);

// ---------------------------------------------------------------------------
// Ed25519 client authentication (OpenSSL — cross-platform)
// Calls platform::readExact / platform::writeExact via the SockFd overload.
// ---------------------------------------------------------------------------

// Forward-declared here; implemented in client_core.cpp using platform::readExact/writeExact.
// ssl may be nullptr for plain connections.
bool performClientAuth(void *ssl, std::uintptr_t sockFd,
                       const std::string &identityPath,
                       bool isDaemon, bool verbose,
                       std::string *errOut = nullptr);

} // namespace ntm
