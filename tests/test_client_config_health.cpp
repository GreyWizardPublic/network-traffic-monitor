// tests/test_client_config_health.cpp — unit tests for cfg_* field parsing in H-lines.

#include "ntm_test.hpp"
#include "../src/ntm_types.hpp"

#include <string>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// cfg_* field parsing via parseHealthLine()
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("cfg: transport tcp is parsed")
{
    auto hs = parseHealthLine("cfg_transport=tcp");
    REQUIRE_EQ(hs.cfgTransport, std::string("tcp"));
}

TEST_CASE("cfg: transport websocket is parsed")
{
    auto hs = parseHealthLine("cfg_transport=websocket");
    REQUIRE_EQ(hs.cfgTransport, std::string("websocket"));
}

TEST_CASE("cfg: transport invalid value is ignored")
{
    auto hs = parseHealthLine("cfg_transport=grpc");
    REQUIRE_EQ(hs.cfgTransport, std::string(""));
}

TEST_CASE("cfg: compress 1 and 0 are parsed")
{
    REQUIRE_EQ(parseHealthLine("cfg_compress=1").cfgCompress, std::int8_t{1});
    REQUIRE_EQ(parseHealthLine("cfg_compress=0").cfgCompress, std::int8_t{0});
}

TEST_CASE("cfg: compress sentinel -1 when absent")
{
    REQUIRE_EQ(parseHealthLine("ver=1.0").cfgCompress, std::int8_t{-1});
}

TEST_CASE("cfg: auto_update 1 and 0 are parsed")
{
    REQUIRE_EQ(parseHealthLine("cfg_auto_update=1").cfgAutoUpdate, std::int8_t{1});
    REQUIRE_EQ(parseHealthLine("cfg_auto_update=0").cfgAutoUpdate, std::int8_t{0});
}

TEST_CASE("cfg: auto_update sentinel -1 when absent")
{
    REQUIRE_EQ(parseHealthLine("ver=1.0").cfgAutoUpdate, std::int8_t{-1});
}

TEST_CASE("cfg: numeric fields are parsed")
{
    auto hs = parseHealthLine(
        "cfg_send_buffer=524288 "
        "cfg_reconnect_attempts=5 "
        "cfg_reconnect_interval=30 "
        "cfg_agg_target=250 "
        "cfg_agg_min_ms=50 "
        "cfg_agg_max_ms=10000 "
        "cfg_agg_max_flows=20000");
    REQUIRE_EQ(hs.cfgSendBuffer, std::uint32_t{524288});
    REQUIRE_EQ(hs.cfgReconnectAttempts, std::uint32_t{5});
    REQUIRE_EQ(hs.cfgReconnectInterval, std::uint32_t{30});
    REQUIRE_EQ(hs.cfgAggTarget, std::uint32_t{250});
    REQUIRE_EQ(hs.cfgAggMinMs, std::uint32_t{50});
    REQUIRE_EQ(hs.cfgAggMaxMs, std::uint32_t{10000});
    REQUIRE_EQ(hs.cfgAggMaxFlows, std::uint32_t{20000});
}

TEST_CASE("cfg: full H-line with cfg and health fields is parsed correctly")
{
    const std::string body =
        "pcap_recv=10000 pcap_drop=5 buf_drop=0 "
        "ver=1.19.0.0 wire_proto=2 platform=linux-amd64 "
        "agg_interval_ms=200 agg_flows=42 "
        "cfg_transport=websocket cfg_compress=1 cfg_send_buffer=0 "
        "cfg_auto_update=0 cfg_reconnect_attempts=10 cfg_reconnect_interval=60 "
        "cfg_agg_target=500 cfg_agg_min_ms=100 cfg_agg_max_ms=5000 cfg_agg_max_flows=10000";
    auto hs = parseHealthLine(body);

    REQUIRE_EQ(hs.pcapRecv, std::uint64_t{10000});
    REQUIRE_EQ(hs.version,  std::string("1.19.0.0"));
    REQUIRE_EQ(hs.cfgTransport, std::string("websocket"));
    REQUIRE_EQ(hs.cfgCompress, std::int8_t{1});
    REQUIRE_EQ(hs.cfgAutoUpdate, std::int8_t{0});
    REQUIRE_EQ(hs.cfgReconnectAttempts, std::uint32_t{10});
    REQUIRE_EQ(hs.cfgAggMaxFlows, std::uint32_t{10000});
}

TEST_CASE("cfg: unknown cfg_xyz key is silently ignored")
{
    auto hs = parseHealthLine("cfg_transport=tcp cfg_xyz_unknown=99 cfg_compress=1");
    REQUIRE_EQ(hs.cfgTransport, std::string("tcp"));
    REQUIRE_EQ(hs.cfgCompress, std::int8_t{1});
}

TEST_CASE("cfg: missing cfg_* fields leave sentinels unchanged")
{
    auto hs = parseHealthLine("pcap_recv=100 ver=1.0 platform=linux-amd64");
    REQUIRE_EQ(hs.cfgTransport, std::string(""));
    REQUIRE_EQ(hs.cfgCompress, std::int8_t{-1});
    REQUIRE_EQ(hs.cfgAutoUpdate, std::int8_t{-1});
    REQUIRE_EQ(hs.cfgSendBuffer, std::uint32_t{0});
}

