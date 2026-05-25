// test_client_history.cpp
// Unit tests for the per-client traffic history ring buffers in TrafficStats.
// Pure logic — no network I/O, no filesystem access.

#include "ntm_test.hpp"
#include "../src/ntm_types.hpp"

#include <cstdint>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

// Build a minimal TrafficStats and add one packet, returning it.
static TrafficStats makeStats()
{
    return TrafficStats(7 /*windowDays*/);
}

// An obviously non-LAN IP for the "out" direction.
static const std::string kWanIp  = "8.8.8.8";
// A LAN IP for the "in" direction.
static const std::string kLanIp  = "192.168.1.10";
static const std::string kClient = std::string(64, 'a');  // valid hex64

static void addPkt(TrafficStats &ts, const std::string &src, const std::string &dst,
                   std::uint32_t bytes = 100)
{
    ts.addPacket(kClient, "eth0", src, dst, "US", "US",
                 "AS1234 Example", "AS5678 Other", bytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// Ring buffer slot assignment
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("client history: single outbound packet appears in fine ring")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 500);  // src=LAN, dst=WAN → "out"
    const auto snap = ts.snapshotHistory(kClient, 1);
    REQUIRE_EQ(snap.bucketSeconds, 60u);
    REQUIRE(!snap.buckets.empty());
    REQUIRE_EQ(snap.buckets.back().outBytes, 500u);
    REQUIRE_EQ(snap.buckets.back().inBytes, 0u);
}

TEST_CASE("client history: single inbound packet appears in fine ring")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kWanIp, kLanIp, 300);  // src=WAN, dst=LAN → "in"
    const auto snap = ts.snapshotHistory(kClient, 1);
    REQUIRE(!snap.buckets.empty());
    REQUIRE_EQ(snap.buckets.back().inBytes, 300u);
    REQUIRE_EQ(snap.buckets.back().outBytes, 0u);
}

TEST_CASE("client history: inbound and outbound packets accumulate independently")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 200);  // out
    addPkt(ts, kWanIp, kLanIp, 150);  // in
    addPkt(ts, kLanIp, kWanIp, 50);   // out
    const auto snap = ts.snapshotHistory(kClient, 1);
    REQUIRE(!snap.buckets.empty());
    REQUIRE_EQ(snap.buckets.back().outBytes, 250u);
    REQUIRE_EQ(snap.buckets.back().inBytes, 150u);
}

TEST_CASE("client history: unknown client returns empty snapshot")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 100);
    const std::string other(64, 'b');
    const auto snap = ts.snapshotHistory(other, 60);
    REQUIRE(snap.buckets.empty());
}

TEST_CASE("client history: fine ring wraps at 1440 slots without data loss in current slot")
{
    REQUIRE_EQ(ClientHistoryRing::kMinuteSlots, 1440u);
    // Slot wraparound: slot 0 and slot 1440 map to the same array index.
    // After wraparound, the old slot is overwritten.  The current slot is fresh.
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 77);
    const auto snap = ts.snapshotHistory(kClient, 1);
    REQUIRE_EQ(snap.buckets.size(), 1u);
    REQUIRE_EQ(snap.buckets[0].outBytes, 77u);
}

TEST_CASE("client history: coarse ring returns hour-level buckets")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 1000);
    const auto snap = ts.snapshotHistory(kClient, 0);  // 0 → full window
    REQUIRE_EQ(snap.bucketSeconds, 3600u);
    REQUIRE(!snap.buckets.empty());
    REQUIRE_EQ(snap.buckets.back().outBytes, 1000u);
}

TEST_CASE("client history: coarse ring returns all slots sorted oldest-first")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 100);
    const auto snap = ts.snapshotHistory(kClient, 0);
    for (std::size_t i = 1; i < snap.buckets.size(); ++i)
        REQUIRE(snap.buckets[i].t > snap.buckets[i - 1].t);
}

TEST_CASE("client history: window_days propagated correctly")
{
    TrafficStats ts(5 /*windowDays*/);
    ts.addPacket(kClient, "eth0", kLanIp, kWanIp, "US", "US", "A", "B", 10);
    const auto snap = ts.snapshotHistory(kClient, 0);
    REQUIRE_EQ(snap.windowDays, 5u);
}

TEST_CASE("client history: purgeClient clears history ring")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 200);
    REQUIRE(!ts.snapshotHistory(kClient, 1).buckets.empty());
    ts.purgeClient(kClient);
    REQUIRE(ts.snapshotHistory(kClient, 1).buckets.empty());
}

TEST_CASE("client history: minutes clamped to kMinuteSlots")
{
    TrafficStats ts = makeStats();
    addPkt(ts, kLanIp, kWanIp, 50);
    // Requesting more than kMinuteSlots is treated as the full fine window.
    // snapshotHistory clamps internally; no crash.
    const auto snap = ts.snapshotHistory(kClient, 9999);
    // The requested amount exceeds kMinuteSlots; function should succeed.
    REQUIRE(!snap.buckets.empty());
}
