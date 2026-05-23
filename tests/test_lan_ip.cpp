// tests/test_lan_ip.cpp — unit tests for ntm::isLanIP() (ntm_types.hpp).
// Covers all RFC-1918 IPv4 ranges, loopback, IPv6 private space, and boundary addresses.

#include "ntm_test.hpp"
#include "../src/ntm_types.hpp"

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 — RFC 1918 private ranges
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanIP: 10.0.0.0/8 — first address is LAN")
{
    REQUIRE(isLanIP("10.0.0.0"));
}

TEST_CASE("isLanIP: 10.0.0.0/8 — midrange address is LAN")
{
    REQUIRE(isLanIP("10.128.64.1"));
}

TEST_CASE("isLanIP: 10.0.0.0/8 — last address is LAN")
{
    REQUIRE(isLanIP("10.255.255.255"));
}

TEST_CASE("isLanIP: 172.16.0.0/12 — first address is LAN")
{
    REQUIRE(isLanIP("172.16.0.0"));
}

TEST_CASE("isLanIP: 172.16.0.0/12 — midrange address is LAN")
{
    REQUIRE(isLanIP("172.20.100.5"));
}

TEST_CASE("isLanIP: 172.16.0.0/12 — last address is LAN (172.31.255.255)")
{
    REQUIRE(isLanIP("172.31.255.255"));
}

TEST_CASE("isLanIP: 172.15.255.255 — just below 172.16 is NOT LAN")
{
    REQUIRE(!isLanIP("172.15.255.255"));
}

TEST_CASE("isLanIP: 172.32.0.0 — just above 172.31 is NOT LAN")
{
    REQUIRE(!isLanIP("172.32.0.0"));
}

TEST_CASE("isLanIP: 192.168.0.0/16 — first address is LAN")
{
    REQUIRE(isLanIP("192.168.0.0"));
}

TEST_CASE("isLanIP: 192.168.0.0/16 — common router address is LAN")
{
    REQUIRE(isLanIP("192.168.1.1"));
}

TEST_CASE("isLanIP: 192.168.0.0/16 — last address is LAN")
{
    REQUIRE(isLanIP("192.168.255.255"));
}

TEST_CASE("isLanIP: 192.167.255.255 — just below 192.168 is NOT LAN")
{
    REQUIRE(!isLanIP("192.167.255.255"));
}

TEST_CASE("isLanIP: 192.169.0.0 — just above 192.168 is NOT LAN")
{
    REQUIRE(!isLanIP("192.169.0.0"));
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 — loopback (127.0.0.0/8)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanIP: 127.0.0.1 — loopback is LAN")
{
    REQUIRE(isLanIP("127.0.0.1"));
}

TEST_CASE("isLanIP: 127.255.255.255 — top of loopback range is LAN")
{
    REQUIRE(isLanIP("127.255.255.255"));
}

TEST_CASE("isLanIP: 128.0.0.1 — just above loopback range is NOT LAN")
{
    REQUIRE(!isLanIP("128.0.0.1"));
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 — public IPs must NOT be classified as LAN
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanIP: 8.8.8.8 — Google DNS is NOT LAN")
{
    REQUIRE(!isLanIP("8.8.8.8"));
}

TEST_CASE("isLanIP: 1.1.1.1 — Cloudflare DNS is NOT LAN")
{
    REQUIRE(!isLanIP("1.1.1.1"));
}

TEST_CASE("isLanIP: 93.184.216.34 — example.com is NOT LAN")
{
    REQUIRE(!isLanIP("93.184.216.34"));
}

TEST_CASE("isLanIP: 0.0.0.0 — all-zeros is NOT LAN")
{
    REQUIRE(!isLanIP("0.0.0.0"));
}

TEST_CASE("isLanIP: 255.255.255.255 — broadcast is NOT LAN")
{
    REQUIRE(!isLanIP("255.255.255.255"));
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv6 — loopback and private ranges
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanIP: ::1 — IPv6 loopback is LAN")
{
    REQUIRE(isLanIP("::1"));
}

TEST_CASE("isLanIP: fc00::1 — ULA (fc00::/7) is LAN")
{
    REQUIRE(isLanIP("fc00::1"));
}

TEST_CASE("isLanIP: fd00::1 — ULA (fd00::/8, within fc00::/7) is LAN")
{
    REQUIRE(isLanIP("fd00::1"));
}

TEST_CASE("isLanIP: fe80::1 — link-local (fe80::/10) is LAN")
{
    REQUIRE(isLanIP("fe80::1"));
}

TEST_CASE("isLanIP: fe80::abcd:1234 — link-local variant is LAN")
{
    REQUIRE(isLanIP("fe80::abcd:1234"));
}

TEST_CASE("isLanIP: 2001:db8::1 — documentation prefix is NOT LAN")
{
    REQUIRE(!isLanIP("2001:db8::1"));
}

TEST_CASE("isLanIP: 2606:4700::1 — Cloudflare IPv6 is NOT LAN")
{
    REQUIRE(!isLanIP("2606:4700::1"));
}

TEST_CASE("isLanIP: :: — all-zeros IPv6 is NOT LAN")
{
    REQUIRE(!isLanIP("::"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Non-parseable / invalid inputs
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanIP: empty string returns false (not LAN)")
{
    REQUIRE(!isLanIP(""));
}

TEST_CASE("isLanIP: garbage string returns false")
{
    REQUIRE(!isLanIP("not_an_ip_address"));
}

TEST_CASE("isLanIP: partial IPv4 returns false")
{
    REQUIRE(!isLanIP("192.168"));
}

TEST_CASE("isLanIP: 'null' sentinel string returns false")
{
    // The X-line sentinel kExtIPNull = "null" must not be misclassified.
    REQUIRE(!isLanIP("null"));
}
