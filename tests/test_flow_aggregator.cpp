// test_flow_aggregator.cpp
// Unit tests for AggFlowKey, FlowMap, and AdaptiveInterval (src/flow_aggregator.hpp).
// No network I/O — pure logic only.

#include "ntm_test.hpp"
#include "../src/flow_aggregator.hpp"

#include <cstdint>
#include <unordered_map>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// AggFlowKey equality and hashing
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("AggFlowKey: identical keys are equal")
{
    AggFlowKey a{"eth0", "10.0.0.1", "8.8.8.8"};
    AggFlowKey b{"eth0", "10.0.0.1", "8.8.8.8"};
    REQUIRE(a == b);
}

TEST_CASE("AggFlowKey: different iface makes keys unequal")
{
    AggFlowKey a{"eth0", "10.0.0.1", "8.8.8.8"};
    AggFlowKey b{"wlan0", "10.0.0.1", "8.8.8.8"};
    REQUIRE(!(a == b));
}

TEST_CASE("AggFlowKey: different src makes keys unequal")
{
    AggFlowKey a{"eth0", "10.0.0.1", "8.8.8.8"};
    AggFlowKey b{"eth0", "10.0.0.2", "8.8.8.8"};
    REQUIRE(!(a == b));
}

TEST_CASE("AggFlowKey: different dst makes keys unequal")
{
    AggFlowKey a{"eth0", "10.0.0.1", "8.8.8.8"};
    AggFlowKey b{"eth0", "10.0.0.1", "1.1.1.1"};
    REQUIRE(!(a == b));
}

TEST_CASE("AggFlowKey: hashing is consistent for equal keys")
{
    AggFlowKeyHash h;
    AggFlowKey a{"eth0", "192.168.1.1", "93.184.216.34"};
    AggFlowKey b{"eth0", "192.168.1.1", "93.184.216.34"};
    REQUIRE_EQ(h(a), h(b));
}

TEST_CASE("AggFlowKey: hashing is distinct for common different keys (collision-free on test set)")
{
    AggFlowKeyHash h;
    AggFlowKey a{"eth0", "10.0.0.1", "8.8.8.8"};
    AggFlowKey b{"eth0", "10.0.0.2", "8.8.8.8"};
    AggFlowKey c{"eth0", "10.0.0.1", "1.1.1.1"};
    AggFlowKey d{"wlan0", "10.0.0.1", "8.8.8.8"};
    // Not guaranteed in general but true for these test strings
    REQUIRE_NE(h(a), h(b));
    REQUIRE_NE(h(a), h(c));
    REQUIRE_NE(h(a), h(d));
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowMap accumulation behaviour
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("FlowMap: empty map has size 0")
{
    FlowMap m;
    REQUIRE_EQ(m.size(), std::size_t{0});
}

TEST_CASE("FlowMap: single packet inserts one entry")
{
    FlowMap m;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 1400u;
    REQUIRE_EQ(m.size(), std::size_t{1});
    REQUIRE_EQ(m.at({"eth0","10.0.0.1","8.8.8.8"}), std::uint64_t{1400});
}

TEST_CASE("FlowMap: same flow accumulates bytes")
{
    FlowMap m;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 1400u;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 600u;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 1000u;
    REQUIRE_EQ(m.size(), std::size_t{1});
    REQUIRE_EQ(m.at({"eth0","10.0.0.1","8.8.8.8"}), std::uint64_t{3000});
}

TEST_CASE("FlowMap: different src IPs produce different entries")
{
    FlowMap m;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 100u;
    m[{"eth0","10.0.0.2","8.8.8.8"}] += 200u;
    REQUIRE_EQ(m.size(), std::size_t{2});
}

TEST_CASE("FlowMap: different dst IPs produce different entries")
{
    FlowMap m;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 100u;
    m[{"eth0","10.0.0.1","1.1.1.1"}] += 200u;
    REQUIRE_EQ(m.size(), std::size_t{2});
}

TEST_CASE("FlowMap: different iface produces different entries")
{
    FlowMap m;
    m[{"eth0","10.0.0.1","8.8.8.8"}] += 100u;
    m[{"wlan0","10.0.0.1","8.8.8.8"}] += 200u;
    REQUIRE_EQ(m.size(), std::size_t{2});
    REQUIRE_EQ(m.at({"eth0","10.0.0.1","8.8.8.8"}),  std::uint64_t{100});
    REQUIRE_EQ(m.at({"wlan0","10.0.0.1","8.8.8.8"}), std::uint64_t{200});
}

TEST_CASE("FlowMap: 1000 distinct flows all present after insertion")
{
    FlowMap m;
    for (int i = 0; i < 1000; ++i)
    {
        std::string src = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
        m[{"eth0", src, "8.8.8.8"}] += static_cast<std::uint64_t>(i + 1) * 100u;
    }
    REQUIRE_EQ(m.size(), std::size_t{1000});
    for (int i = 0; i < 1000; ++i)
    {
        std::string src = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
        REQUIRE_EQ(m.at({"eth0", src, "8.8.8.8"}),
                   static_cast<std::uint64_t>(i + 1) * 100u);
    }
}

TEST_CASE("FlowMap: swap clears source and transfers entries")
{
    FlowMap src;
    src[{"eth0","10.0.0.1","8.8.8.8"}] += 500u;
    FlowMap dst;
    std::swap(src, dst);
    REQUIRE_EQ(src.size(), std::size_t{0});
    REQUIRE_EQ(dst.size(), std::size_t{1});
    REQUIRE_EQ(dst.at({"eth0","10.0.0.1","8.8.8.8"}), std::uint64_t{500});
}

// ═══════════════════════════════════════════════════════════════════════════
// AdaptiveInterval — defaults and construction
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("AdaptiveInterval: default construction uses builtin defaults")
{
    AdaptiveInterval ai;
    REQUIRE_EQ(ai.config().targetLinesPerSec, std::uint32_t{500});
    REQUIRE_EQ(ai.config().minIntervalMs,     std::uint32_t{100});
    REQUIRE_EQ(ai.config().maxIntervalMs,     std::uint32_t{5000});
}

TEST_CASE("AdaptiveInterval: initial interval equals minIntervalMs")
{
    AdaptiveInterval ai;
    REQUIRE_EQ(ai.intervalMs(), ai.config().minIntervalMs);
}

TEST_CASE("AdaptiveInterval: custom config is stored correctly")
{
    AdaptiveInterval::Config cfg;
    cfg.targetLinesPerSec = 200;
    cfg.minIntervalMs = 50;
    cfg.maxIntervalMs = 10000;
    AdaptiveInterval ai{cfg};
    REQUIRE_EQ(ai.config().targetLinesPerSec, std::uint32_t{200});
    REQUIRE_EQ(ai.config().minIntervalMs,     std::uint32_t{50});
    REQUIRE_EQ(ai.config().maxIntervalMs,     std::uint32_t{10000});
    REQUIRE_EQ(ai.intervalMs(), std::uint32_t{50});
}

// ═══════════════════════════════════════════════════════════════════════════
// AdaptiveInterval — update logic
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("AdaptiveInterval: zero flows moves interval toward max")
{
    AdaptiveInterval ai;
    std::uint32_t prev = ai.intervalMs();
    ai.update(0);
    REQUIRE(ai.intervalMs() > prev);  // moved toward max
}

TEST_CASE("AdaptiveInterval: zero flows never exceeds maxIntervalMs")
{
    AdaptiveInterval ai;
    for (int i = 0; i < 100; ++i) ai.update(0);
    REQUIRE(ai.intervalMs() <= ai.config().maxIntervalMs);
}

TEST_CASE("AdaptiveInterval: zero flows eventually reaches maxIntervalMs")
{
    AdaptiveInterval ai;
    for (int i = 0; i < 200; ++i) ai.update(0);
    // EMA(0.3) + uint32_t truncation: converges to within ~10 ms of max
    REQUIRE(ai.intervalMs() >= ai.config().maxIntervalMs - 10u);
}

TEST_CASE("AdaptiveInterval: flows below target keeps interval at min")
{
    // With target=500 and 10 flows, desired_ms=20, clamped to 100 (min).
    // Interval should stay at min.
    AdaptiveInterval ai;
    for (int i = 0; i < 30; ++i) ai.update(10);
    REQUIRE_EQ(ai.intervalMs(), ai.config().minIntervalMs);
}

TEST_CASE("AdaptiveInterval: flows equal to target stays near 1000ms")
{
    // 500 flows with target=500 → desired=1000ms.
    // After convergence the interval should be close to 1000.
    AdaptiveInterval ai;
    for (int i = 0; i < 100; ++i) ai.update(500);
    // Allow ±5 ms for floating-point rounding
    REQUIRE(ai.intervalMs() >= 995u);
    REQUIRE(ai.intervalMs() <= 1005u);
}

TEST_CASE("AdaptiveInterval: very high flows approaches maxIntervalMs")
{
    // 50000 flows with target=500 → desired=100000ms → clamped to max 5000.
    AdaptiveInterval ai;
    for (int i = 0; i < 200; ++i) ai.update(50000);
    // uint32_t truncation of EMA may land a few ms below exact max
    REQUIRE(ai.intervalMs() >= ai.config().maxIntervalMs - 10u);
}

TEST_CASE("AdaptiveInterval: interval never goes below minIntervalMs")
{
    AdaptiveInterval ai;
    for (int i = 0; i < 100; ++i) ai.update(1);    // tiny flows
    REQUIRE(ai.intervalMs() >= ai.config().minIntervalMs);
}

TEST_CASE("AdaptiveInterval: interval never exceeds maxIntervalMs")
{
    AdaptiveInterval ai;
    for (int i = 0; i < 100; ++i) ai.update(1000000);  // huge flows
    REQUIRE(ai.intervalMs() <= ai.config().maxIntervalMs);
}

TEST_CASE("AdaptiveInterval: reset returns to minIntervalMs")
{
    AdaptiveInterval ai;
    for (int i = 0; i < 50; ++i) ai.update(0);   // push toward max
    REQUIRE(ai.intervalMs() > ai.config().minIntervalMs);
    ai.reset();
    REQUIRE_EQ(ai.intervalMs(), ai.config().minIntervalMs);
}

TEST_CASE("AdaptiveInterval: EMA smoothing — single update moves only 30% toward desired")
{
    // Start at min=100. Target=500 lines, 500 flows → desired=1000ms.
    // After one update: 0.7*100 + 0.3*1000 = 370.
    AdaptiveInterval ai;
    ai.update(500);
    REQUIRE_EQ(ai.intervalMs(), std::uint32_t{370});
}

TEST_CASE("AdaptiveInterval: convergence after traffic change")
{
    // Start with high traffic (50000 flows → max interval), then switch to
    // moderate traffic (500 flows → 1000ms). Should converge within 50 steps.
    AdaptiveInterval::Config cfg;
    cfg.targetLinesPerSec = 500;
    cfg.minIntervalMs = 100;
    cfg.maxIntervalMs = 5000;
    AdaptiveInterval ai{cfg};
    for (int i = 0; i < 200; ++i) ai.update(50000);
    REQUIRE(ai.intervalMs() >= cfg.maxIntervalMs - 10u);

    for (int i = 0; i < 100; ++i) ai.update(500);
    REQUIRE(ai.intervalMs() >= 990u);
    REQUIRE(ai.intervalMs() <= 1010u);
}
