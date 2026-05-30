// test_health_stats.cpp
// Unit tests for parseHealthLine() (ntm_types.hpp) covering:
//   - Non-regression: existing fields still parsed correctly
//   - New fields: agg_interval_ms, agg_flows
//   - Edge cases: unknown fields, empty input, malformed values, field ordering

#include "ntm_test.hpp"

// ntm_types.hpp includes POSIX sockets for isLanIP() — include the stubs
// needed to compile it in a test binary without the full server link.
#include "../src/ntm_types.hpp"

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// Non-regression: existing fields
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHealthLine: empty body yields all-zero struct")
{
    auto hs = parseHealthLine("");
    REQUIRE_EQ(hs.pcapRecv,         std::uint64_t{0});
    REQUIRE_EQ(hs.pcapDrop,         std::uint64_t{0});
    REQUIRE_EQ(hs.bufDrop,          std::uint64_t{0});
    REQUIRE_EQ(hs.wireProtoVersion, 0u);
    REQUIRE(hs.version.empty());
    REQUIRE(hs.platform.empty());
    REQUIRE_EQ(hs.aggIntervalMs,    std::uint32_t{0});
    REQUIRE_EQ(hs.aggFlows,         std::uint32_t{0});
    REQUIRE_EQ(hs.reportedAtSec,    std::int64_t{-1}); // not set by parser
}

TEST_CASE("parseHealthLine: pcap_recv parsed correctly")
{
    auto hs = parseHealthLine("pcap_recv=1234567890");
    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{1234567890});
}

TEST_CASE("parseHealthLine: pcap_drop parsed correctly")
{
    auto hs = parseHealthLine("pcap_drop=9876");
    REQUIRE_EQ(hs.pcapDrop, std::uint64_t{9876});
}

TEST_CASE("parseHealthLine: buf_drop parsed correctly")
{
    auto hs = parseHealthLine("buf_drop=42");
    REQUIRE_EQ(hs.bufDrop, std::uint64_t{42});
}

TEST_CASE("parseHealthLine: wire_proto parsed correctly")
{
    auto hs = parseHealthLine("wire_proto=2");
    REQUIRE_EQ(hs.wireProtoVersion, 2u);
}

TEST_CASE("parseHealthLine: ver string field parsed correctly")
{
    auto hs = parseHealthLine("ver=1.10.0");
    REQUIRE_EQ(hs.version, std::string{"1.10.0"});
}

TEST_CASE("parseHealthLine: platform string field parsed correctly")
{
    auto hs = parseHealthLine("platform=linux-amd64");
    REQUIRE_EQ(hs.platform, std::string{"linux-amd64"});
}

TEST_CASE("parseHealthLine: full typical H-line body (non-regression)")
{
    auto hs = parseHealthLine(
        "pcap_recv=2847281 pcap_drop=0 buf_drop=12 "
        "ver=1.9.0 wire_proto=1 platform=linux-amd64");
    REQUIRE_EQ(hs.pcapRecv,         std::uint64_t{2847281});
    REQUIRE_EQ(hs.pcapDrop,         std::uint64_t{0});
    REQUIRE_EQ(hs.bufDrop,          std::uint64_t{12});
    REQUIRE_EQ(hs.wireProtoVersion, 1u);
    REQUIRE_EQ(hs.version,          std::string{"1.9.0"});
    REQUIRE_EQ(hs.platform,         std::string{"linux-amd64"});
    REQUIRE_EQ(hs.aggIntervalMs,    std::uint32_t{0});   // absent → 0
    REQUIRE_EQ(hs.aggFlows,         std::uint32_t{0});
}

// ═══════════════════════════════════════════════════════════════════════════
// New aggregation fields
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHealthLine: agg_interval_ms parsed correctly")
{
    auto hs = parseHealthLine("agg_interval_ms=1200");
    REQUIRE_EQ(hs.aggIntervalMs, std::uint32_t{1200});
}

TEST_CASE("parseHealthLine: agg_flows parsed correctly")
{
    auto hs = parseHealthLine("agg_flows=47");
    REQUIRE_EQ(hs.aggFlows, std::uint32_t{47});
}

TEST_CASE("parseHealthLine: agg_interval_ms=0 stays zero (not reported)")
{
    auto hs = parseHealthLine("agg_interval_ms=0");
    REQUIRE_EQ(hs.aggIntervalMs, std::uint32_t{0});
}

TEST_CASE("parseHealthLine: full new H-line body with agg fields")
{
    auto hs = parseHealthLine(
        "pcap_recv=5000000 pcap_drop=0 buf_drop=0 "
        "ver=1.10.0 wire_proto=1 platform=linux-amd64 "
        "agg_interval_ms=1200 agg_flows=47");
    REQUIRE_EQ(hs.pcapRecv,         std::uint64_t{5000000});
    REQUIRE_EQ(hs.version,          std::string{"1.10.0"});
    REQUIRE_EQ(hs.aggIntervalMs,    std::uint32_t{1200});
    REQUIRE_EQ(hs.aggFlows,         std::uint32_t{47});
}

TEST_CASE("parseHealthLine: large agg_interval_ms value (max interval)")
{
    auto hs = parseHealthLine("agg_interval_ms=5000");
    REQUIRE_EQ(hs.aggIntervalMs, std::uint32_t{5000});
}

TEST_CASE("parseHealthLine: large agg_flows value")
{
    auto hs = parseHealthLine("agg_flows=10000");
    REQUIRE_EQ(hs.aggFlows, std::uint32_t{10000});
}

// ═══════════════════════════════════════════════════════════════════════════
// Forward compatibility: unknown fields
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHealthLine: unknown keys are silently ignored")
{
    auto hs = parseHealthLine(
        "pcap_recv=100 future_field=xyz another_new=999 ver=1.2.3");
    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{100});
    REQUIRE_EQ(hs.version,  std::string{"1.2.3"});
    // No crash, no corruption
}

TEST_CASE("parseHealthLine: only unknown keys yields zero struct")
{
    auto hs = parseHealthLine("unknown_a=1 unknown_b=hello");
    REQUIRE_EQ(hs.pcapRecv,      std::uint64_t{0});
    REQUIRE_EQ(hs.aggIntervalMs, std::uint32_t{0});
    REQUIRE(hs.version.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Field ordering independence
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHealthLine: agg fields first, others after")
{
    auto hs = parseHealthLine(
        "agg_interval_ms=800 agg_flows=30 pcap_recv=9999 ver=1.10.0");
    REQUIRE_EQ(hs.aggIntervalMs, std::uint32_t{800});
    REQUIRE_EQ(hs.aggFlows,      std::uint32_t{30});
    REQUIRE_EQ(hs.pcapRecv,      std::uint64_t{9999});
    REQUIRE_EQ(hs.version,       std::string{"1.10.0"});
}

TEST_CASE("parseHealthLine: fields in reverse order")
{
    auto hs = parseHealthLine(
        "agg_flows=55 agg_interval_ms=2000 wire_proto=1 "
        "platform=windows-amd64 ver=1.10.0 buf_drop=3 pcap_drop=1 pcap_recv=500");
    REQUIRE_EQ(hs.aggFlows,         std::uint32_t{55});
    REQUIRE_EQ(hs.aggIntervalMs,    std::uint32_t{2000});
    REQUIRE_EQ(hs.wireProtoVersion, 1u);
    REQUIRE_EQ(hs.platform,         std::string{"windows-amd64"});
    REQUIRE_EQ(hs.version,          std::string{"1.10.0"});
    REQUIRE_EQ(hs.bufDrop,          std::uint64_t{3});
    REQUIRE_EQ(hs.pcapDrop,         std::uint64_t{1});
    REQUIRE_EQ(hs.pcapRecv,         std::uint64_t{500});
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed / edge-case input robustness
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHealthLine: malformed numeric field does not crash")
{
    // Non-numeric value for a numeric field → silently ignored (stays default 0)
    auto hs = parseHealthLine("pcap_recv=not_a_number");
    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{0});
}

TEST_CASE("parseHealthLine: key without value is skipped")
{
    // No '=' separator — entire token treated as unknown key, skipped
    auto hs = parseHealthLine("pcap_recv=100 badtoken pcap_drop=5");
    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{100});
    REQUIRE_EQ(hs.pcapDrop, std::uint64_t{5});
}

TEST_CASE("parseHealthLine: extra whitespace is tolerated")
{
    auto hs = parseHealthLine("  pcap_recv=77  agg_flows=12  ");
    REQUIRE_EQ(hs.pcapRecv,  std::uint64_t{77});
    REQUIRE_EQ(hs.aggFlows,  std::uint32_t{12});
}

TEST_CASE("parseHealthLine: carriage return stripped (CRLF line endings)")
{
    auto hs = parseHealthLine("pcap_recv=88\r");
    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{88});
}

TEST_CASE("parseHealthLine: reportedAtSec is NOT set by parser (stays -1)")
{
    // The caller is responsible for stamping reportedAtSec.
    auto hs = parseHealthLine("pcap_recv=1 ver=1.0.0");
    REQUIRE_EQ(hs.reportedAtSec, std::int64_t{-1});
}

// L-3 regression: ver and platform fields must be capped at 64 characters.
TEST_CASE("parseHealthLine: ver field capped at 64 chars (L-3)")
{
    const std::string long_ver(200, 'A');
    auto hs = parseHealthLine("ver=" + long_ver);
    REQUIRE_EQ(hs.version.size(), std::size_t{64});
}

TEST_CASE("parseHealthLine: platform field capped at 64 chars (L-3)")
{
    const std::string long_plat(200, 'B');
    auto hs = parseHealthLine("platform=" + long_plat);
    REQUIRE_EQ(hs.platform.size(), std::size_t{64});
}

TEST_CASE("parseHealthLine: ver field within limit preserved exactly (L-3)")
{
    auto hs = parseHealthLine("ver=1.19.0.1");
    REQUIRE_EQ(hs.version, std::string{"1.19.0.1"});
}

// ═══════════════════════════════════════════════════════════════════════════
// Derived computation: output rate (dashboard calculation)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Aggregation output rate calculation: 47 flows / 1.2s ≈ 39/s")
{
    ClientHealthStats hs;
    hs.aggIntervalMs = 1200;
    hs.aggFlows      = 47;
    // The dashboard computes: Math.round(agg_flows / (agg_interval_ms / 1000))
    double rate = static_cast<double>(hs.aggFlows)
                / (static_cast<double>(hs.aggIntervalMs) / 1000.0);
    int rounded = static_cast<int>(rate + 0.5);
    REQUIRE_EQ(rounded, 39);
}

TEST_CASE("Aggregation output rate calculation: 500 flows / 1.0s = 500/s (at target)")
{
    ClientHealthStats hs;
    hs.aggIntervalMs = 1000;
    hs.aggFlows      = 500;
    double rate = static_cast<double>(hs.aggFlows)
                / (static_cast<double>(hs.aggIntervalMs) / 1000.0);
    int rounded = static_cast<int>(rate + 0.5);
    REQUIRE_EQ(rounded, 500);
}

TEST_CASE("Aggregation output rate calculation: 2400 flows / 4.8s = 500/s (heavy traffic)")
{
    ClientHealthStats hs;
    hs.aggIntervalMs = 4800;
    hs.aggFlows      = 2400;
    double rate = static_cast<double>(hs.aggFlows)
                / (static_cast<double>(hs.aggIntervalMs) / 1000.0);
    int rounded = static_cast<int>(rate + 0.5);
    REQUIRE_EQ(rounded, 500);
}
