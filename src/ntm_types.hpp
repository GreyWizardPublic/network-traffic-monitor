#pragma once

// ntm_types.hpp — aggregation data types and process-wide logging,
// shared between server_core and web_dashboard compilation units.

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <syslog.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ntm
{

// Returns true if ip (IPv4 or IPv6 string) is in RFC 1918 / loopback / ULA /
// link-local space. Non-parseable strings return false.
inline bool isLanIP(const std::string &ip)
{
    struct in_addr a4;
    if (::inet_pton(AF_INET, ip.c_str(), &a4) == 1)
    {
        std::uint32_t a = ntohl(a4.s_addr);
        if ((a & 0xFF000000u) == 0x7F000000u) return true; // 127.0.0.0/8
        if ((a & 0xFF000000u) == 0x0A000000u) return true; // 10.0.0.0/8
        if ((a & 0xFFF00000u) == 0xAC100000u) return true; // 172.16.0.0/12
        if ((a & 0xFFFF0000u) == 0xC0A80000u) return true; // 192.168.0.0/16
        return false;
    }
    struct in6_addr a6;
    if (::inet_pton(AF_INET6, ip.c_str(), &a6) == 1)
    {
        static const std::uint8_t lo6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (std::memcmp(&a6, lo6, 16) == 0) return true;       // ::1
        if ((a6.s6_addr[0] & 0xFEu) == 0xFCu) return true;    // fc00::/7 ULA
        if (a6.s6_addr[0] == 0xFEu &&
            (a6.s6_addr[1] & 0xC0u) == 0x80u) return true;    // fe80::/10 link-local
        return false;
    }
    return false;
}

// Per-client health stats reported via the H protocol line.
// Session-scoped: values are cumulative since the current connection was established.
// The server stores only the latest H line per client (replace, never accumulate).
struct ClientHealthStats
{
    std::uint64_t pcapRecv{0};       // packets delivered to the capture callback (ps_recv)
    std::uint64_t pcapDrop{0};       // packets dropped by kernel ring-buffer (ps_drop)
    std::uint64_t bufDrop{0};        // packets the client received but couldn't queue to server
    std::int64_t  reportedAtSec{-1};    // epoch-seconds when the last H line was received
    std::string   version;              // client version string from "ver=" field in H line
    unsigned      wireProtoVersion{0};  // from wire_proto= field; 0 = not yet reported
};

// Auth-version mismatch connection attempt. Recorded when a client presents an
// unrecognised auth version byte (as distinct from a wrong-key failure, which is a
// security event and is not stored here).
struct ProtoRejectionRecord
{
    std::string   peerIp;           // connecting IP address
    std::uint8_t  attemptedVersion; // auth version byte the client sent
    std::int64_t  atSec;            // epoch-seconds of the attempt
};

// Shared registry: maps a client's LAN IP to its Ed25519 hex client ID, tracks each
// client's external (WAN) IP for LAN-group scoping, and stores the latest health stats.
// Written by connectionThread on auth and on X/A/H lines; read via local snapshots in
// the data-processing hot path and via mutex-protected snapshot in the web thread.
struct ClientRegistry
{
    mutable std::mutex mtx;
    std::unordered_map<std::string, std::string>       ipToClientId;       // LAN IP → hex clientId
    std::unordered_map<std::string, std::string>       clientToExternalIp; // hex clientId → external IP or "null"
    std::unordered_map<std::string, ClientHealthStats> clientHealth;        // hex clientId → latest H stats
    std::deque<ProtoRejectionRecord>                   protoRejections;     // capped at 20 most-recent

    // Remove all entries for clientId (called on session end and on X-line re-announce).
    void removeClient(const std::string &clientId)
    {
        if (clientId.empty()) return;
        std::lock_guard<std::mutex> lk(mtx);
        for (auto it = ipToClientId.begin(); it != ipToClientId.end(); )
            it = (it->second == clientId) ? ipToClientId.erase(it) : std::next(it);
        clientToExternalIp.erase(clientId);
        clientHealth.erase(clientId);
    }
};

// Shared store for wire-protocol client authentication.
// Populated at startup from the allowed-keys file; new entries appended at
// runtime via POST /api/admin/client/register without server restart.
// Connection threads hold a shared_lock during key lookup; the web endpoint
// holds a unique_lock during insert to prevent torn reads.
struct AllowedClientsStore
{
    mutable std::shared_mutex mu;
    std::set<std::string>                          keys;      // raw 32-byte binary keys
    std::unordered_map<std::string, std::string>   nicknames; // lowercase hex64 → display name
    std::string                                    filePath;
};

// Thread-safe set of IP addresses belonging to monitoring infrastructure
// (the server itself, or dashboard browser/app clients). Used at JSON
// serialisation time to classify entity flows as overhead vs. regular traffic.
struct MonitoringIpSet
{
    struct Entry { std::string ip; std::int64_t lastSeen{0}; };

    mutable std::mutex mtx;
    std::unordered_map<std::string, std::int64_t> ips; // ip → last_seen epoch

    void add(const std::string &ip)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::lock_guard<std::mutex> lk(mtx);
        ips[ip] = now;
    }

    // Returns IP → last_seen pairs (copy under lock).
    std::vector<Entry> snapshot() const
    {
        std::lock_guard<std::mutex> lk(mtx);
        std::vector<Entry> out;
        out.reserve(ips.size());
        for (const auto &kv : ips)
            out.push_back({kv.first, kv.second});
        return out;
    }

    // Returns just the IP strings as an unordered_set (for fast membership tests).
    std::unordered_set<std::string> ipSet() const
    {
        std::lock_guard<std::mutex> lk(mtx);
        std::unordered_set<std::string> out;
        out.reserve(ips.size());
        for (const auto &kv : ips) out.insert(kv.first);
        return out;
    }
};

inline constexpr unsigned kAggregationWindowDaysDefault = 7;

// Process-wide logging mode set in runServer() before threads start.
// Daemon mode → syslog; foreground mode → stderr.
inline std::atomic<bool> g_daemon{false};
inline std::atomic<bool> g_verbose{false};

enum class LogLevel { Info, Warn, Err };

inline void serverLog(LogLevel lvl, const char *fmt, ...)
{
    if (lvl == LogLevel::Info && !g_verbose.load(std::memory_order_relaxed))
        return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    if (g_daemon.load(std::memory_order_relaxed))
    {
        int prio = (lvl == LogLevel::Err) ? LOG_ERR
                 : (lvl == LogLevel::Warn) ? LOG_WARNING
                 : LOG_INFO;
        syslog(prio, "%s", buf);
    }
    else
    {
        std::cerr << buf;
        if (n > 0 && buf[n - 1] != '\n')
            std::cerr << '\n';
    }
}

struct FlowKey
{
    std::string src;
    std::string dst;

    bool operator==(const FlowKey &other) const noexcept
    {
        return src == other.src && dst == other.dst;
    }
};

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey &k) const noexcept
    {
        std::hash<std::string> h;
        return (h(k.src) * 1315423911u) ^ h(k.dst);
    }
};

struct Counter
{
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
};

// Per-(src,dst) flow statistics including basic timing.
struct FlowStats
{
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::int64_t firstSeenSec{-1};
    std::int64_t lastSeenSec{-1};
};

using InterfaceTotals       = std::unordered_map<std::string, Counter>;
using FlowMap               = std::unordered_map<FlowKey, FlowStats, FlowKeyHash>;
using InterfaceFlows        = std::unordered_map<std::string, FlowMap>;
using CountryFlowMap        = std::unordered_map<FlowKey, Counter, FlowKeyHash>;
using InterfaceCountryFlows = std::unordered_map<std::string, CountryFlowMap>;
using EntityFlowMap         = std::unordered_map<FlowKey, Counter, FlowKeyHash>;
using InterfaceEntityFlows  = std::unordered_map<std::string, EntityFlowMap>;

struct DayBucket
{
    std::int64_t dayIndex{0};
    InterfaceTotals totals;
    InterfaceFlows flows;
    InterfaceCountryFlows countryFlows;
    InterfaceEntityFlows entityFlows;
};

class TrafficStats
{
public:
    using InterfaceTotals       = ntm::InterfaceTotals;
    using FlowMap               = ntm::FlowMap;
    using InterfaceFlows        = ntm::InterfaceFlows;
    using InterfaceCountryFlows = ntm::InterfaceCountryFlows;
    using InterfaceEntityFlows  = ntm::InterfaceEntityFlows;
    using TimePoint             = std::chrono::system_clock::time_point;

    explicit TrafficStats(unsigned windowDays,
                         std::size_t maxFlowEntriesPerKey = 100000,
                         std::size_t maxEntityFlowEntriesPerKey = 100000,
                         std::size_t maxIfacesPerClient = 256)
        : windowDays_(windowDays > 0 ? windowDays : kAggregationWindowDaysDefault)
        , maxFlowEntriesPerKey_(maxFlowEntriesPerKey > 0 ? maxFlowEntriesPerKey : 1)
        , maxEntityFlowEntriesPerKey_(maxEntityFlowEntriesPerKey > 0 ? maxEntityFlowEntriesPerKey : 1)
        , maxIfacesPerClient_(maxIfacesPerClient > 0 ? maxIfacesPerClient : 1)
    {
    }

    TimePoint getAggregationWindowStart() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dayBuckets_.empty())
            return std::chrono::system_clock::now();
        return TimePoint(std::chrono::seconds(dayBuckets_.front().dayIndex * 86400));
    }

    // UB-1: result of addPacket() so the caller can rate-limit operator warnings
    // when a client tries to register more than maxIfacesPerClient_ interfaces.
    enum class AddResult { Accepted, IfaceCapExceeded };

    AddResult addPacket(const std::string &clientId,
                        const std::string &iface,
                        const std::string &src,
                        const std::string &dst,
                        const std::string &srcCountry,
                        const std::string &dstCountry,
                        const std::string &srcEntity,
                        const std::string &dstEntity,
                        std::uint32_t length)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::system_clock::now();
        const auto epochSec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        const std::int64_t dayIndex = (epochSec >= 0) ? (epochSec / 86400) : ((epochSec - 86399) / 86400);
        const std::string ciKey = clientId + "|" + iface;
        const FlowKey flowKey{src, dst};
        const FlowKey countryKey{srcCountry, dstCountry};
        const FlowKey entityKey{srcEntity, dstEntity};

        // UB-1: enforce per-client iface cardinality cap BEFORE touching any map.
        auto &ifaceSet = clientIfaces_[clientId];
        const bool isNewIface = (ifaceSet.find(iface) == ifaceSet.end());
        if (isNewIface && ifaceSet.size() >= maxIfacesPerClient_)
        {
            ++ifaceRejectCount_[clientId];
            return AddResult::IfaceCapExceeded;
        }
        if (isNewIface)
            ifaceSet.insert(iface);

        if (dayBuckets_.empty() || dayBuckets_.back().dayIndex != dayIndex)
            dayBuckets_.push_back(DayBucket{dayIndex, {}, {}, {}, {}});

        DayBucket &bucket = dayBuckets_.back();
        auto &total = bucket.totals[ciKey];
        auto &flowMap = bucket.flows[ciKey];
        auto &entityFlowMap = bucket.entityFlows[ciKey];
        if (flowMap.size() >= maxFlowEntriesPerKey_ && flowMap.find(flowKey) == flowMap.end())
        {
            auto it = std::min_element(flowMap.begin(), flowMap.end(),
                [](const auto &a, const auto &b) { return a.second.bytes < b.second.bytes; });
            if (it != flowMap.end())
                flowMap.erase(it);
        }
        if (entityFlowMap.size() >= maxEntityFlowEntriesPerKey_ && entityFlowMap.find(entityKey) == entityFlowMap.end())
        {
            auto it = std::min_element(entityFlowMap.begin(), entityFlowMap.end(),
                [](const auto &a, const auto &b) { return a.second.bytes < b.second.bytes; });
            if (it != entityFlowMap.end())
                entityFlowMap.erase(it);
        }
        auto &flowCounter = flowMap[flowKey];
        auto &countryCounter = bucket.countryFlows[ciKey][countryKey];
        auto &entityCounter = entityFlowMap[entityKey];

        if (wouldOverflow(total.packets, 1u, total.bytes, length) ||
            wouldOverflow(flowCounter.packets, 1u, flowCounter.bytes, length) ||
            wouldOverflow(countryCounter.packets, 1u, countryCounter.bytes, length) ||
            wouldOverflow(entityCounter.packets, 1u, entityCounter.bytes, length))
        {
            resetClientUnlocked(clientId);
            total = bucket.totals[ciKey];
            flowMap = bucket.flows[ciKey];
            entityFlowMap = bucket.entityFlows[ciKey];
            flowCounter = flowMap[flowKey];
            countryCounter = bucket.countryFlows[ciKey][countryKey];
            entityCounter = entityFlowMap[entityKey];
        }

        if (flowCounter.firstSeenSec < 0)
            flowCounter.firstSeenSec = epochSec;
        flowCounter.lastSeenSec = epochSec;

        total.packets += 1;
        total.bytes += length;
        flowCounter.packets += 1;
        flowCounter.bytes += length;
        countryCounter.packets += 1;
        countryCounter.bytes += length;
        entityCounter.packets += 1;
        entityCounter.bytes += length;

        while (dayBuckets_.size() > windowDays_)
            dayBuckets_.pop_front();
        return AddResult::Accepted;
    }

    // UB-1: lookup the rejection counter for one client.
    std::uint64_t getIfaceRejectCount(const std::string &clientId) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ifaceRejectCount_.find(clientId);
        return it == ifaceRejectCount_.end() ? 0u : it->second;
    }

    // Erase all historical data for one client across every day bucket.
    // Returns true if any data was present. Safe to call concurrently with addPacket/snapshot.
    bool purgeClient(const std::string &clientId)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string prefix = clientId + "|";
        bool found = false;
        for (const auto &b : dayBuckets_)
        {
            for (const auto &kv : b.totals)
            {
                if (kv.first.size() >= prefix.size() &&
                    kv.first.compare(0, prefix.size(), prefix) == 0)
                {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        resetClientUnlocked(clientId);
        return found;
    }

    void snapshot(InterfaceTotals &totalsOut,
                  InterfaceFlows &flowsOut,
                  InterfaceCountryFlows &countryFlowsOut,
                  InterfaceEntityFlows &entityFlowsOut,
                  TimePoint *windowStartOut = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        totalsOut.clear();
        flowsOut.clear();
        countryFlowsOut.clear();
        entityFlowsOut.clear();
        for (const DayBucket &b : dayBuckets_)
        {
            for (const auto &kv : b.totals)
            {
                auto &c = totalsOut[kv.first];
                c.packets += kv.second.packets;
                c.bytes += kv.second.bytes;
            }
            for (const auto &kv : b.flows)
            {
                for (const auto &fk : kv.second)
                {
                    auto &c = flowsOut[kv.first][fk.first];
                    c.packets += fk.second.packets;
                    c.bytes += fk.second.bytes;
                    if (fk.second.firstSeenSec >= 0)
                    {
                        if (c.firstSeenSec < 0 || fk.second.firstSeenSec < c.firstSeenSec)
                            c.firstSeenSec = fk.second.firstSeenSec;
                    }
                    if (fk.second.lastSeenSec >= 0)
                    {
                        if (c.lastSeenSec < 0 || fk.second.lastSeenSec > c.lastSeenSec)
                            c.lastSeenSec = fk.second.lastSeenSec;
                    }
                }
            }
            for (const auto &kv : b.countryFlows)
            {
                for (const auto &ck : kv.second)
                {
                    auto &c = countryFlowsOut[kv.first][ck.first];
                    c.packets += ck.second.packets;
                    c.bytes += ck.second.bytes;
                }
            }
            for (const auto &kv : b.entityFlows)
            {
                for (const auto &ek : kv.second)
                {
                    auto &c = entityFlowsOut[kv.first][ek.first];
                    c.packets += ek.second.packets;
                    c.bytes += ek.second.bytes;
                }
            }
        }
        if (windowStartOut && !dayBuckets_.empty())
            *windowStartOut = TimePoint(std::chrono::seconds(dayBuckets_.front().dayIndex * 86400));
        else if (windowStartOut)
            *windowStartOut = std::chrono::system_clock::now();
    }

private:
    static bool wouldOverflow(std::uint64_t packets, std::uint64_t addPackets,
                              std::uint64_t bytes, std::uint64_t addBytes)
    {
        return (addPackets > 0 && packets > UINT64_MAX - addPackets) ||
               (addBytes > 0 && bytes > UINT64_MAX - addBytes);
    }

    void resetClientUnlocked(const std::string &clientId)
    {
        const std::string prefix = clientId + "|";
        for (DayBucket &b : dayBuckets_)
        {
            for (auto it = b.totals.begin(); it != b.totals.end(); )
            {
                if (it->first.size() >= prefix.size() && it->first.compare(0, prefix.size(), prefix) == 0)
                    it = b.totals.erase(it);
                else
                    ++it;
            }
            for (auto it = b.flows.begin(); it != b.flows.end(); )
            {
                if (it->first.size() >= prefix.size() && it->first.compare(0, prefix.size(), prefix) == 0)
                    it = b.flows.erase(it);
                else
                    ++it;
            }
            for (auto it = b.countryFlows.begin(); it != b.countryFlows.end(); )
            {
                if (it->first.size() >= prefix.size() && it->first.compare(0, prefix.size(), prefix) == 0)
                    it = b.countryFlows.erase(it);
                else
                    ++it;
            }
            for (auto it = b.entityFlows.begin(); it != b.entityFlows.end(); )
            {
                if (it->first.size() >= prefix.size() && it->first.compare(0, prefix.size(), prefix) == 0)
                    it = b.entityFlows.erase(it);
                else
                    ++it;
            }
        }
        // UB-1: reset per-client iface bookkeeping so the cap counts from zero again.
        clientIfaces_.erase(clientId);
        ifaceRejectCount_.erase(clientId);
    }

    mutable std::mutex mutex_;
    unsigned windowDays_;
    std::size_t maxFlowEntriesPerKey_;
    std::size_t maxEntityFlowEntriesPerKey_;
    std::size_t maxIfacesPerClient_;
    std::deque<DayBucket> dayBuckets_;

    // UB-1: per-client iface cardinality tracking across the rolling window.
    std::unordered_map<std::string, std::unordered_set<std::string>> clientIfaces_;
    std::unordered_map<std::string, std::uint64_t> ifaceRejectCount_;
};

} // namespace ntm
