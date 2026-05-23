#pragma once
// flow_aggregator.hpp — Client-side per-packet flow accumulation and adaptive
// flush interval controller.  Pure logic: no I/O, no threading, no OpenSSL.
// Designed to be fully unit-testable in isolation.

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

namespace ntm
{

// ---------------------------------------------------------------------------
// FlowKey — unique (iface, src_ip, dst_ip) tuple
// ---------------------------------------------------------------------------

struct FlowKey
{
    std::string iface;
    std::string srcIp;
    std::string dstIp;

    bool operator==(const FlowKey &o) const noexcept
    {
        return iface == o.iface && srcIp == o.srcIp && dstIp == o.dstIp;
    }
};

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey &k) const noexcept
    {
        // Boost-style hash_combine using all three fields
        auto h = std::hash<std::string>{};
        std::size_t seed = h(k.iface);
        seed ^= h(k.srcIp) + 0x9e3779b9u + (seed << 6) + (seed >> 2);
        seed ^= h(k.dstIp) + 0x9e3779b9u + (seed << 6) + (seed >> 2);
        return seed;
    }
};

using FlowMap = std::unordered_map<FlowKey, std::uint64_t, FlowKeyHash>;

// ---------------------------------------------------------------------------
// AdaptiveInterval — feedback controller for the flush interval.
//
// After each timer-triggered flush, call update(flows_emitted) to adjust
// the next interval so that the output rate converges to targetLinesPerSec.
//
// Algorithm:
//   desired_ms = clamp(flows * 1000 / target, min, max)
//   next_ms    = EMA(current_ms, desired_ms, alpha=0.3)
//              = 0.7 * current + 0.3 * desired   (clamped)
//
// Properties:
//   - Zero flows  → backs off to maxIntervalMs (no traffic, save bandwidth).
//   - Many flows  → extends interval to shed output rate toward target.
//   - Few flows   → clamps at minIntervalMs (responsive during quiet periods).
//   - EMA smoothing prevents oscillation on bursty traffic.
// ---------------------------------------------------------------------------

class AdaptiveInterval
{
public:
    struct Config
    {
        std::uint32_t targetLinesPerSec{500};  // target max D-lines/sec output
        std::uint32_t minIntervalMs{100};      // 10 Hz — minimum flush rate
        std::uint32_t maxIntervalMs{5000};     // 0.2 Hz — maximum staleness
    };

    AdaptiveInterval() noexcept
        : cfg_{}
        , currentMs_(cfg_.minIntervalMs)
    {}

    explicit AdaptiveInterval(Config cfg) noexcept
        : cfg_(cfg)
        , currentMs_(cfg.minIntervalMs)   // start responsive
    {}

    // Call after each timer-triggered flush with the number of D-lines emitted.
    // Do NOT call after a forced flush (max-flows cap) — the interval shouldn't
    // adapt based on a degenerate burst sample.
    void update(std::uint32_t flowsEmitted) noexcept
    {
        std::uint32_t desired;
        if (flowsEmitted == 0 || cfg_.targetLinesPerSec == 0)
        {
            desired = cfg_.maxIntervalMs;
        }
        else
        {
            // desired_ms = flows * 1000 / target
            // ensures flows / (desired_ms/1000) == targetLinesPerSec
            std::uint64_t d = (static_cast<std::uint64_t>(flowsEmitted) * 1000u)
                              / cfg_.targetLinesPerSec;
            desired = (d > cfg_.maxIntervalMs) ? cfg_.maxIntervalMs
                    : (d < cfg_.minIntervalMs) ? cfg_.minIntervalMs
                    : static_cast<std::uint32_t>(d);
        }

        // EMA: move 30 % toward desired each cycle
        std::uint32_t next = static_cast<std::uint32_t>(
            0.7f * static_cast<float>(currentMs_)
          + 0.3f * static_cast<float>(desired));

        currentMs_ = std::clamp(next, cfg_.minIntervalMs, cfg_.maxIntervalMs);
    }

    // Current flush interval (milliseconds).
    std::uint32_t intervalMs() const noexcept { return currentMs_; }

    // Direct read/write for serialisation or testing.
    const Config &config() const noexcept { return cfg_; }

    // Reset to initial state (e.g. after reconnect — fresh connection, start responsive).
    void reset() noexcept { currentMs_ = cfg_.minIntervalMs; }

private:
    Config        cfg_;
    std::uint32_t currentMs_;
};

} // namespace ntm
