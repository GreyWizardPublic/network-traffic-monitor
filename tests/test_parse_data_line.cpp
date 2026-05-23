// tests/test_parse_data_line.cpp — unit tests for ntm::parseDataLine()
// (proto_client_server.hpp). Covers the hot-path D-line parser used by ntm-server
// to ingest packet observations from ntm-client.

#include "ntm_test.hpp"
#include "../src/proto_client_server.hpp"

#include <string>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// Happy-path: valid D-line bodies
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseDataLine: typical D-line body parses all four fields")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 10.0.0.1 8.8.8.8 1400", m));
    REQUIRE_EQ(m.iface, std::string{"eth0"});
    REQUIRE_EQ(m.srcIp, std::string{"10.0.0.1"});
    REQUIRE_EQ(m.dstIp, std::string{"8.8.8.8"});
    REQUIRE_EQ(m.bytes, std::uint32_t{1400});
}

TEST_CASE("parseDataLine: bytes = 0 is valid")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 10.0.0.1 1.1.1.1 0", m));
    REQUIRE_EQ(m.bytes, std::uint32_t{0});
}

TEST_CASE("parseDataLine: bytes = UINT32_MAX is valid")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 10.0.0.1 1.1.1.1 4294967295", m));
    REQUIRE_EQ(m.bytes, std::uint32_t{4294967295u});
}

TEST_CASE("parseDataLine: IPv6 src and dst accepted")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 fe80::1 2001:db8::1 500", m));
    REQUIRE_EQ(m.srcIp, std::string{"fe80::1"});
    REQUIRE_EQ(m.dstIp, std::string{"2001:db8::1"});
    REQUIRE_EQ(m.bytes, std::uint32_t{500});
}

TEST_CASE("parseDataLine: interface name with digits is accepted")
{
    PacketMeta m;
    REQUIRE(parseDataLine("enp3s0 192.168.1.1 93.184.216.34 800", m));
    REQUIRE_EQ(m.iface, std::string{"enp3s0"});
}

TEST_CASE("parseDataLine: leading whitespace is skipped")
{
    PacketMeta m;
    REQUIRE(parseDataLine("  eth0 10.0.0.1 8.8.8.8 1500", m));
    REQUIRE_EQ(m.iface, std::string{"eth0"});
    REQUIRE_EQ(m.bytes, std::uint32_t{1500});
}

TEST_CASE("parseDataLine: multiple spaces between fields are collapsed")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0  10.0.0.1   8.8.8.8  1200", m));
    REQUIRE_EQ(m.iface, std::string{"eth0"});
    REQUIRE_EQ(m.bytes, std::uint32_t{1200});
}

TEST_CASE("parseDataLine: tab separators are accepted")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0\t10.0.0.1\t8.8.8.8\t700", m));
    REQUIRE_EQ(m.bytes, std::uint32_t{700});
}

TEST_CASE("parseDataLine: CRLF trailing is tolerated")
{
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 10.0.0.1 8.8.8.8 600\r\n", m));
    REQUIRE_EQ(m.bytes, std::uint32_t{600});
}

// ═══════════════════════════════════════════════════════════════════════════
// Error cases: missing or malformed fields
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseDataLine: empty string returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("", m));
}

TEST_CASE("parseDataLine: only whitespace returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("   ", m));
}

TEST_CASE("parseDataLine: one field only returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0", m));
}

TEST_CASE("parseDataLine: two fields only returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0 10.0.0.1", m));
}

TEST_CASE("parseDataLine: three fields only returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0 10.0.0.1 8.8.8.8", m));
}

TEST_CASE("parseDataLine: non-numeric bytes field returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0 10.0.0.1 8.8.8.8 notanumber", m));
}

TEST_CASE("parseDataLine: bytes field is empty (whitespace only after dst) returns false")
{
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0 10.0.0.1 8.8.8.8 ", m));
}

// ═══════════════════════════════════════════════════════════════════════════
// Overflow / boundary checks
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseDataLine: bytes = UINT32_MAX + 1 returns false")
{
    PacketMeta m;
    // 4294967296 = UINT32_MAX + 1
    REQUIRE(!parseDataLine("eth0 10.0.0.1 8.8.8.8 4294967296", m));
}

// ═══════════════════════════════════════════════════════════════════════════
// Field length limits
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseDataLine: iface exactly at kMaxIfaceLabelLen (64) is accepted")
{
    std::string iface(kMaxIfaceLabelLen, 'x');
    PacketMeta m;
    REQUIRE(parseDataLine(iface + " 10.0.0.1 8.8.8.8 100", m));
    REQUIRE_EQ(m.iface.size(), kMaxIfaceLabelLen);
}

TEST_CASE("parseDataLine: iface one over kMaxIfaceLabelLen (65) is rejected")
{
    std::string iface(kMaxIfaceLabelLen + 1, 'x');
    PacketMeta m;
    REQUIRE(!parseDataLine(iface + " 10.0.0.1 8.8.8.8 100", m));
}

TEST_CASE("parseDataLine: src IP exactly at kMaxIpLabelLen (50) is accepted")
{
    // Construct a 50-character src string (not a real IP, but length limit is enforced)
    std::string src(kMaxIpLabelLen, '1');
    PacketMeta m;
    REQUIRE(parseDataLine("eth0 " + src + " 8.8.8.8 100", m));
    REQUIRE_EQ(m.srcIp.size(), kMaxIpLabelLen);
}

TEST_CASE("parseDataLine: src IP one over kMaxIpLabelLen (51) is rejected")
{
    std::string src(kMaxIpLabelLen + 1, '1');
    PacketMeta m;
    REQUIRE(!parseDataLine("eth0 " + src + " 8.8.8.8 100", m));
}

TEST_CASE("parseDataLine: custom limits override defaults")
{
    // Custom limit: max iface = 3, max ip = 7
    PacketMeta m;
    REQUIRE(parseDataLine("eth 1.2.3.4 5.6.7.8 99", m, 3, 7));
    REQUIRE(!parseDataLine("eth0 1.2.3.4 5.6.7.8 99", m, 3, 7)); // iface too long
}
