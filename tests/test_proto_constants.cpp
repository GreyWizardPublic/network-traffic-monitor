// tests/test_proto_constants.cpp — invariant checks for wire-protocol constants
// (proto_client_server.hpp). These act as regression guards: a value that
// changes unexpectedly (e.g. via a typo, merge conflict, or accidental edit)
// breaks a test here before it breaks a live connection.

#include "ntm_test.hpp"
#include "../src/proto_client_server.hpp"

#include <cstring>
#include <string>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// Port numbers
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kDefaultPort is 5555")
{
    REQUIRE_EQ(kDefaultPort, std::uint16_t{5555});
}

TEST_CASE("proto constants: kDemoPort is 12345")
{
    REQUIRE_EQ(kDemoPort, std::uint16_t{12345});
}

// ═══════════════════════════════════════════════════════════════════════════
// Protocol versions
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kWireProtoVersion is 2")
{
    REQUIRE_EQ(kWireProtoVersion, 2u);
}

TEST_CASE("proto constants: kApiVersion is 9")
{
    REQUIRE_EQ(kApiVersion, 9u);
}

TEST_CASE("proto constants: kAuthVersionV2 < kAuthVersionV3")
{
    REQUIRE(kAuthVersionV2 < kAuthVersionV3);
}

// ═══════════════════════════════════════════════════════════════════════════
// Line prefixes — wire format
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kDataLinePrefix is 'D ' (2 chars)")
{
    REQUIRE_EQ(std::string{kDataLinePrefix}, std::string{"D "});
}

TEST_CASE("proto constants: kHealthLinePrefix is 'H ' (2 chars)")
{
    REQUIRE_EQ(std::string{kHealthLinePrefix}, std::string{"H "});
}

TEST_CASE("proto constants: kExtIPLinePrefix is 'X ' (2 chars)")
{
    REQUIRE_EQ(std::string{kExtIPLinePrefix}, std::string{"X "});
}

TEST_CASE("proto constants: kAddrLinePrefix is 'A ' (2 chars)")
{
    REQUIRE_EQ(std::string{kAddrLinePrefix}, std::string{"A "});
}

TEST_CASE("proto constants: kExtIPNull is 'null'")
{
    REQUIRE_EQ(std::string{kExtIPNull}, std::string{"null"});
}

// ═══════════════════════════════════════════════════════════════════════════
// ALPN identifiers
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kAlpnNtmWire is 'ntm-wire'")
{
    REQUIRE_EQ(std::string{kAlpnNtmWire}, std::string{"ntm-wire"});
}

TEST_CASE("proto constants: kAlpnHttp11 is 'http/1.1'")
{
    REQUIRE_EQ(std::string{kAlpnHttp11}, std::string{"http/1.1"});
}

// ═══════════════════════════════════════════════════════════════════════════
// Auth prefix — length must match actual string
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kAuthSignPrefixV2 is 'NTM-AUTH-v2'")
{
    REQUIRE_EQ(std::string{kAuthSignPrefixV2}, std::string{"NTM-AUTH-v2"});
}

TEST_CASE("proto constants: kAuthSignPrefixV2Len matches strlen of kAuthSignPrefixV2")
{
    REQUIRE_EQ(kAuthSignPrefixV2Len, std::strlen(kAuthSignPrefixV2));
}

TEST_CASE("proto constants: kAuthSignPrefixV2Len is 11")
{
    // "NTM-AUTH-v2" has 11 characters — explicit regression guard.
    REQUIRE_EQ(kAuthSignPrefixV2Len, std::size_t{11});
}

// ═══════════════════════════════════════════════════════════════════════════
// Auth binary sizes
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kAuthPubkeyLen is 32 (Ed25519 public key)")
{
    REQUIRE_EQ(kAuthPubkeyLen, std::size_t{32});
}

TEST_CASE("proto constants: kAuthSignatureLen is 64 (Ed25519 signature)")
{
    REQUIRE_EQ(kAuthSignatureLen, std::size_t{64});
}

TEST_CASE("proto constants: kAuthNonceLen is 32")
{
    REQUIRE_EQ(kAuthNonceLen, std::size_t{32});
}

// ═══════════════════════════════════════════════════════════════════════════
// Capability flags — bit positions must not collide
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kCapNone is 0x00")
{
    REQUIRE_EQ(kCapNone, std::uint8_t{0x00});
}

TEST_CASE("proto constants: kCapZlib is 0x01 (bit 0)")
{
    REQUIRE_EQ(kCapZlib, std::uint8_t{0x01});
}

TEST_CASE("proto constants: kCapNone & kCapZlib == 0 (flags don't collide)")
{
    REQUIRE_EQ(static_cast<std::uint8_t>(kCapNone & kCapZlib), std::uint8_t{0});
}

// ═══════════════════════════════════════════════════════════════════════════
// Session and rate-limit timings
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kHealthIntervalSec is 30")
{
    REQUIRE_EQ(kHealthIntervalSec, 30u);
}

TEST_CASE("proto constants: kMaxSessionSeconds is 6 hours (21600)")
{
    REQUIRE_EQ(kMaxSessionSeconds, std::uint64_t{6 * 3600});
}

TEST_CASE("proto constants: kDemoSessionSec is 900 (15 minutes)")
{
    REQUIRE_EQ(kDemoSessionSec, std::int64_t{900});
}

TEST_CASE("proto constants: kAnnounceRateLimitSec is 30")
{
    REQUIRE_EQ(kAnnounceRateLimitSec, 30u);
}

// ═══════════════════════════════════════════════════════════════════════════
// Label length limits — guard against accidental relaxation
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto constants: kMaxIfaceLabelLen is 64")
{
    REQUIRE_EQ(kMaxIfaceLabelLen, std::size_t{64});
}

TEST_CASE("proto constants: kMaxIpLabelLen is 50")
{
    REQUIRE_EQ(kMaxIpLabelLen, std::size_t{50});
}

TEST_CASE("proto constants: kMaxAnnounceAddressesPerSession is 64")
{
    REQUIRE_EQ(kMaxAnnounceAddressesPerSession, std::size_t{64});
}
