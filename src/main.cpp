// ntm-server: headless aggregation daemon / foreground process
// Receives PacketMeta lines from ntm-client over TCP and aggregates
// by interface, IP pair, and country pair.

#include "proto_client_server.hpp"
#include "httplib.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <syslog.h>
#include <sys/time.h>
#include <thread>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <algorithm>
#include <sys/stat.h>

#include <functional>

#include "ip_range_resolver.hpp"

namespace ntm
{

// Server aggregation: rolling window by day (configurable). Default days if not in config.
inline constexpr unsigned kAggregationWindowDaysDefault = 7;

// H2: process-wide logging mode set in main()/runServer().
// In daemon mode, log lines go to syslog (stderr is /dev/null after daemonize()).
// In foreground mode, log lines go to stderr.
// g_verbose enables non-essential ("info") log lines.
inline std::atomic<bool> g_daemon{false};
inline std::atomic<bool> g_verbose{false};

enum class LogLevel { Info, Warn, Err };

// Single logging path: syslog (daemon) or stderr (foreground). Use printf-style format.
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

// Server boundary limits and startup paths: defaults when not set in config (see docs and ntm-server.conf.example).
struct ServerConfig
{
    // Startup / TLS / auth (config file or CLI; CLI overrides config).
    std::uint16_t port{kDefaultPort};
    std::string client_bind; // empty = INADDR_ANY
    std::string allowed_keys;
    std::string cert;
    std::string key;
    bool require_tls{false};
    bool verbose{false};
    // Web dashboard (HTTPS, LAN-only).
    std::uint16_t web_port{8443};
    std::string web_bind{"0.0.0.0"};
    std::string web_token;          // optional bearer token; empty = no token auth
    unsigned web_rate_limit_rpm{30}; // max requests per IP per minute (0 = unlimited)
    // Boundary limits.
    unsigned aggregation_window_days{kAggregationWindowDaysDefault};
    std::size_t max_recv_buffer_bytes{1024 * 1024};  // 1 MiB

    // IPRangeResolver / IPDataUpdater configuration (replaces libmaxminddb).
    // The local cache file is the gzipped TSV pulled from iptoasn.com; the
    // background updater re-downloads it every ip_db_update_interval_days.
    std::string ip_db_path{"/var/lib/ntm-server/ip2asn-combined.tsv.gz"};
    std::string ip_db_url{"https://iptoasn.com/data/ip2asn-combined.tsv.gz"};
    unsigned ip_db_update_interval_days{7};
    bool ip_db_auto_update{true};
    std::size_t max_flow_entries_per_key{100000};
    std::size_t max_entity_flow_entries_per_key{100000};
    // UB-1: hard cap on distinct iface names per client. Prevents an authenticated
    // (or otherwise accepted) client from growing TrafficStats without bound by
    // submitting D-lines with arbitrarily many fake iface names.
    std::size_t max_ifaces_per_client{256};
    std::size_t max_entity_lines_in_summary{50000};
    std::size_t max_snapshot_entries_for_print{200000};
    std::size_t max_iface_len{64};
    std::size_t max_ip_len{50};
    std::size_t max_concurrent_connections{1000};
    std::size_t max_connections_per_ip{20};
    unsigned idle_timeout_seconds{300};
    unsigned max_d_lines_per_second_per_connection{20000};
};

// Tracks concurrent connections per client IP to limit one host exhausting the connection pool.
class PerIPConnectionLimiter
{
public:
    explicit PerIPConnectionLimiter(std::size_t maxPerIP)
        : maxPerIP_(maxPerIP > 0 ? maxPerIP : 1)
    {
    }

    bool tryAcquire(const std::string &ip)
    {
        if (ip.empty())
            return true;
        std::lock_guard<std::mutex> lock(mutex_);
        if (counts_[ip] >= maxPerIP_)
            return false;
        counts_[ip]++;
        return true;
    }

    void release(const std::string &ip)
    {
        if (ip.empty())
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = counts_.find(ip);
        if (it != counts_.end())
        {
            if (it->second <= 1u)
                counts_.erase(it);
            else
                it->second--;
        }
    }

private:
    std::size_t maxPerIP_;
    std::mutex mutex_;
    std::unordered_map<std::string, unsigned> counts_;
};

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

// Per-(src,dst) flow statistics including basic timing to estimate how often
// two endpoints communicate over the aggregation window.
struct FlowStats
{
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    // First and last observation time for this flow in epoch seconds.
    // -1 means "not yet seen".
    std::int64_t firstSeenSec{-1};
    std::int64_t lastSeenSec{-1};
};

using InterfaceTotals = std::unordered_map<std::string, Counter>;
using FlowMap = std::unordered_map<FlowKey, FlowStats, FlowKeyHash>;
using InterfaceFlows = std::unordered_map<std::string, FlowMap>;
using CountryFlowMap = std::unordered_map<FlowKey, Counter, FlowKeyHash>;
using InterfaceCountryFlows = std::unordered_map<std::string, CountryFlowMap>;
using EntityFlowMap = std::unordered_map<FlowKey, Counter, FlowKeyHash>;
using InterfaceEntityFlows = std::unordered_map<std::string, EntityFlowMap>;

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
    using InterfaceTotals = ntm::InterfaceTotals;
    using FlowMap = ntm::FlowMap;
    using InterfaceFlows = ntm::InterfaceFlows;
    using InterfaceCountryFlows = ntm::InterfaceCountryFlows;
    using InterfaceEntityFlows = ntm::InterfaceEntityFlows;
    using TimePoint = std::chrono::system_clock::time_point;

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

    // Aggregation window start (midnight UTC of oldest day in the rolling window).
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

    // Rolling window: stats tracked by day; when window + 1 days exist, only the oldest day is dropped.
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

        // UB-1: enforce per-client iface cardinality cap BEFORE touching any map
        // that would otherwise allocate a new entry. We use clientIfaces_ as the
        // source of truth (it persists across day-bucket rollovers so a malicious
        // client can't just wait for midnight to reset the cap).
        auto &ifaceSet = clientIfaces_[clientId];
        const bool isNewIface = (ifaceSet.find(iface) == ifaceSet.end());
        if (isNewIface && ifaceSet.size() >= maxIfacesPerClient_)
        {
            // Throttle the rejection counter and let the caller decide when to log.
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

        // Update per-flow counters and basic timing to capture how often
        // this source and destination communicate within the aggregation window.
        if (flowCounter.firstSeenSec < 0)
        {
            flowCounter.firstSeenSec = epochSec;
        }
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

    // UB-1: lookup the rejection counter for one client (used by the connection
    // worker to log only occasionally, not on every dropped D-line). The counter is
    // never reset; the absolute number is fine for monitoring.
    std::uint64_t getIfaceRejectCount(const std::string &clientId) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ifaceRejectCount_.find(clientId);
        return it == ifaceRejectCount_.end() ? 0u : it->second;
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

    // Remove all statistics for this client from every day bucket (clean reset for overflow).
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
        // UB-1: reset the per-client iface bookkeeping too, otherwise the cap would
        // count rejected/cleared interfaces forever even though their stats are gone.
        clientIfaces_.erase(clientId);
        ifaceRejectCount_.erase(clientId);
    }

    mutable std::mutex mutex_;
    unsigned windowDays_;
    std::size_t maxFlowEntriesPerKey_;
    std::size_t maxEntityFlowEntriesPerKey_;
    std::size_t maxIfacesPerClient_;
    std::deque<DayBucket> dayBuckets_;

    // UB-1: track per-client iface cardinality across the rolling window. We do not
    // remove a client's entry until the rolling window has aged out the last bucket
    // that referenced it (see snapshot/reset). The key is the clientId itself; the
    // value is the set of iface names the client has registered. Bounded per client
    // by maxIfacesPerClient_; bounded across clients by allowed_keys cardinality (or
    // by per-IP / global connection limits in unauth mode).
    std::unordered_map<std::string, std::unordered_set<std::string>> clientIfaces_;
    // Per-(clientId,iface) counter of rejections; rate-limited via a logger threshold.
    std::unordered_map<std::string, std::uint64_t> ifaceRejectCount_;
};

// NOTE: GeoIPResolver and EntityResolver have been replaced by the unified
// IPRangeResolver + IPDataUpdater pair (see src/ip_range_resolver.hpp). The
// new implementation uses iptoasn.com's CC0 ip2asn-combined.tsv.gz instead of
// MaxMind's GeoLite2 MMDB files, and auto-refreshes the local cache every 7
// days by default. libmaxminddb is no longer a dependency.

static std::atomic<bool> g_running{true};

void handleSignal(int)
{
    g_running.store(false);
}

void daemonize()
{
#ifdef __unix__
    pid_t pid = fork();
    if (pid < 0)
    {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        std::exit(EXIT_SUCCESS);
    }

    if (setsid() < 0)
    {
        std::perror("setsid");
        std::exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0)
    {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        std::exit(EXIT_SUCCESS);
    }

    umask(0);
    // NEW-N6: report (but don't fatally fail on) chdir/dup2 errors. The daemon can
    // continue if these fail, but operators want a clue in the journal.
    if (chdir("/") != 0)
    {
        serverLog(LogLevel::Warn, "ntm-server: chdir(\"/\") failed: %s", std::strerror(errno));
    }

    int fd = ::open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        if (dup2(fd, STDIN_FILENO) < 0)
            serverLog(LogLevel::Warn, "ntm-server: dup2(stdin) failed: %s", std::strerror(errno));
        if (dup2(fd, STDOUT_FILENO) < 0)
            serverLog(LogLevel::Warn, "ntm-server: dup2(stdout) failed: %s", std::strerror(errno));
        if (dup2(fd, STDERR_FILENO) < 0)
            serverLog(LogLevel::Warn, "ntm-server: dup2(stderr) failed: %s", std::strerror(errno));
        if (fd > 2)
            close(fd);
    }
    else
    {
        serverLog(LogLevel::Warn, "ntm-server: cannot open /dev/null for stdio redirection: %s",
                  std::strerror(errno));
    }
#else
    std::cerr << "Daemon mode is only implemented on Unix-like systems.\n";
#endif
}

bool parseDataLine(const std::string &line, PacketMeta &out,
                  std::size_t maxIfaceLen, std::size_t maxIpLen)
{
    if (line.empty())
        return false;

    std::string iface;
    std::string src;
    std::string dst;
    std::string bytesStr;

    std::istringstream iss(line);
    if (!(iss >> iface >> src >> dst >> bytesStr))
    {
        return false;
    }

    if (maxIfaceLen == 0) maxIfaceLen = 64;
    if (maxIpLen == 0) maxIpLen = 50;
    if (iface.size() > maxIfaceLen || src.size() > maxIpLen || dst.size() > maxIpLen)
        return false;

    char *end = nullptr;
    unsigned long val = std::strtoul(bytesStr.c_str(), &end, 10);
    if (end == bytesStr.c_str())
    {
        return false;
    }
    if (val > static_cast<unsigned long>(UINT32_MAX))
        return false;

    out.iface = std::move(iface);
    out.srcIp = std::move(src);
    out.dstIp = std::move(dst);
    out.bytes = static_cast<std::uint32_t>(val);
    return true;
}

// Load allowed client public keys from file: one 64-char hex line per key (32 bytes).
// M5: lookups against this set use constant-time comparison via constantTimeContains()
//     to avoid leaking which keys are present through string-compare timing.
// NEW-N7: malformed entries are reported via serverLog so operators don't silently
//     drop keys due to fat-fingered hex.
using AllowedKeysSet = std::set<std::string>;

// M5: constant-time membership check. Walks every entry and uses CRYPTO_memcmp on
// equal-length keys; cost is O(N * 32) but the set is typically tiny (<<1000) and
// auth happens once per connection, so this is negligible vs network RTT.
static bool allowedKeysContains(const AllowedKeysSet &keys, const std::string &needle)
{
    if (needle.size() != kAuthPubkeyLen)
        return false;
    // NEW-N11: branchless accumulator. We OR the per-key comparison result into
    // `found` without an `if`, so the per-key inner work has no early-exit
    // branch on a successful match. Total runtime depends only on the size of
    // the allow-list (which is bounded), not on whether/where the match occurs.
    volatile unsigned found = 0u;
    for (const std::string &k : keys)
    {
        if (k.size() != kAuthPubkeyLen)
            continue;
        const unsigned eq =
            (CRYPTO_memcmp(k.data(), needle.data(), kAuthPubkeyLen) == 0) ? 1u : 0u;
        found |= eq;
    }
    return found != 0u;
}
static AllowedKeysSet loadAllowedKeys(const std::string &path)
{
    AllowedKeysSet out;
    if (path.empty())
        return out;
    std::ifstream f(path);
    if (!f)
    {
        serverLog(LogLevel::Err, "ntm-server: cannot open allowed-keys file: %s", path.c_str());
        return out;
    }
    std::string line;
    std::size_t lineNo = 0;
    while (std::getline(f, line))
    {
        ++lineNo;
        // Trim and skip empty / comment
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        if (line.size() != 64)
        {
            serverLog(LogLevel::Warn,
                      "ntm-server: %s line %zu: ignoring entry with %zu chars (expected 64-char hex)",
                      path.c_str(), lineNo, line.size());
            continue;
        }
        bool bad = false;
        for (char c : line)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                bad = true;
                break;
            }
        }
        if (bad)
        {
            serverLog(LogLevel::Warn,
                      "ntm-server: %s line %zu: ignoring entry with non-hex characters",
                      path.c_str(), lineNo);
            continue;
        }
        // Decode hex to 32 bytes and store as string for set lookup
        std::string raw;
        raw.reserve(32);
        for (std::size_t i = 0; i < 64; i += 2)
        {
            int hi = (line[i] >= 'a') ? (line[i] - 'a' + 10) : (line[i] >= 'A') ? (line[i] - 'A' + 10) : (line[i] - '0');
            int lo = (line[i + 1] >= 'a') ? (line[i + 1] - 'a' + 10) : (line[i + 1] >= 'A') ? (line[i + 1] - 'A' + 10) : (line[i + 1] - '0');
            raw.push_back(static_cast<char>((hi << 4) | lo));
        }
        out.insert(raw);
    }
    return out;
}


// Read exactly n bytes via SSL_read (or recv if ssl is null). Returns true if read succeeded.
static bool readExact(SSL *ssl, int fd, void *buf, std::size_t n)
{
    static constexpr std::size_t kMaxIOBytes = 2 * 1024 * 1024;
    if (n == 0 || n > kMaxIOBytes)
        return false;
    std::uint8_t *p = static_cast<std::uint8_t *>(buf);
    while (n > 0)
    {
        int r;
        if (ssl)
            r = SSL_read(ssl, p, static_cast<int>(n));
        else
            r = static_cast<int>(::recv(fd, p, n, 0));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

// Write exactly n bytes via SSL_write (or send if ssl is null). Returns true if write succeeded.
static bool writeExact(SSL *ssl, int fd, const void *buf, std::size_t n)
{
    static constexpr std::size_t kMaxIOBytes = 2 * 1024 * 1024;
    if (n == 0 || n > kMaxIOBytes)
        return false;
    const std::uint8_t *p = static_cast<const std::uint8_t *>(buf);
    while (n > 0)
    {
        int r;
        if (ssl)
            r = SSL_write(ssl, p, static_cast<int>(n));
        else
            r = static_cast<int>(::send(fd, p, n, MSG_NOSIGNAL));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

// Verify auth message and return clientId (hex of pubkey) or empty on failure.
static std::string verifyClientAuth(SSL *ssl, int clientFd, const AllowedKeysSet &allowedKeys)
{
    if (allowedKeys.empty())
        return {};

    std::uint8_t version = 0;
    if (!readExact(ssl, clientFd, &version, 1))
        return {};

    auto pubkeyToIdHex = [](const std::string &pubkeyRaw) -> std::string
    {
        static const char hex[] = "0123456789abcdef";
        std::string clientId;
        clientId.reserve(64);
        for (unsigned char b : pubkeyRaw)
        {
            clientId += hex[b >> 4];
            clientId += hex[b & 0xf];
        }
        return clientId;
    };

    if (version == kAuthVersionV2)
    {
        // Server challenge nonce
        std::uint8_t nonce[kAuthNonceLen];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1)
            return {};
        if (!writeExact(ssl, clientFd, nonce, sizeof(nonce)))
            return {};

        // Client response: pubkey + signature over prefix+nonce
        std::uint8_t resp[kAuthPubkeyLen + kAuthSignatureLen];
        if (!readExact(ssl, clientFd, resp, sizeof(resp)))
            return {};

        std::string pubkeyRaw(reinterpret_cast<const char *>(resp), kAuthPubkeyLen);
        // M5: constant-time membership check (avoids std::set::find timing leak).
        if (!allowedKeysContains(allowedKeys, pubkeyRaw))
            return {};

        std::string toVerify(reinterpret_cast<const char *>(kAuthSignPrefixV2), kAuthSignPrefixV2Len);
        toVerify.append(reinterpret_cast<const char *>(nonce), sizeof(nonce));

        const unsigned char *sig = reinterpret_cast<const unsigned char *>(resp + kAuthPubkeyLen);
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                     reinterpret_cast<const unsigned char *>(pubkeyRaw.data()),
                                                     pubkeyRaw.size());
        if (!pkey)
            return {};
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
                 && EVP_DigestVerify(ctx, sig, kAuthSignatureLen,
                                    reinterpret_cast<const unsigned char *>(toVerify.data()),
                                    toVerify.size()) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        if (!ok)
            return {};
        return pubkeyToIdHex(pubkeyRaw);
    }

    return {};
}

// NEW-N8: known config keys. Used to warn on typos and to detect "config opened
// but contains nothing recognized" so operators don't silently get pure defaults.
static const std::set<std::string> &knownServerConfigKeys()
{
    static const std::set<std::string> keys = {
        "port", "client_bind",
        "allowed_keys", "cert", "key",
        "require_tls", "verbose",
        "web_port", "web_bind", "web_token", "web_rate_limit_rpm",
        "aggregation_window_days", "max_recv_buffer_bytes",
        "ip_db_path", "ip_db_url", "ip_db_update_interval_days", "ip_db_auto_update",
        "max_flow_entries_per_key", "max_entity_flow_entries_per_key",
        "max_ifaces_per_client",
        "max_entity_lines_in_summary", "max_snapshot_entries_for_print",
        "max_iface_len", "max_ip_len",
        "max_concurrent_connections", "max_connections_per_ip",
        "idle_timeout_seconds", "max_d_lines_per_second_per_connection",
    };
    return keys;
}

// Load server config (key=value). Returns config with defaults for missing keys or file.
// M7: 'ok' is set to false only when the caller asked for a specific config path that
//     could not be opened (so the caller can fail fast instead of silently using defaults).
//     If configPath is empty (no --config provided) defaults are returned with ok=true.
// NEW-N8: 'recognizedOut' (if non-null) receives the count of recognized key=value
//     lines from the file so the caller can warn on a misnamed/empty file.
static ServerConfig loadServerConfig(const std::string &configPath, bool *ok = nullptr,
                                     std::size_t *recognizedOut = nullptr)
{
    ServerConfig cfg;
    if (ok) *ok = true;
    if (recognizedOut) *recognizedOut = 0;
    if (configPath.empty())
        return cfg;
    std::ifstream f(configPath);
    if (!f)
    {
        if (ok) *ok = false;
        return cfg;
    }
    const auto &kKnown = knownServerConfigKeys();
    std::size_t recognized = 0;
    std::string line;
    std::size_t lineNo = 0;
    while (std::getline(f, line))
    {
        ++lineNo;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#')
            continue;
        std::size_t eq = line.find('=', start);
        if (eq == std::string::npos)
            continue;
        std::string key = line.substr(start, eq - start);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.pop_back();
        if (kKnown.find(key) == kKnown.end())
        {
            // NEW-N8: surface unknown keys so a typo (e.g. "alowed_keys") doesn't go silent.
            // We can't use serverLog here yet (g_daemon may not be set during initial main()
            // parse), so route through stderr; it gets captured by systemd in foreground.
            std::cerr << "ntm-server: " << configPath << " line " << lineNo
                      << ": unknown config key '" << key << "' (ignored)\n";
            continue;
        }
        ++recognized;
        std::string val = line.substr(eq + 1);
        start = val.find_first_not_of(" \t");
        if (start != std::string::npos)
            val = val.substr(start);
        if (val.empty() && key != "allowed_keys" && key != "cert" && key != "key" && key != "web_token")
            continue;
        try
        {
            unsigned long u = 0;
            if (key == "port")
            {
                u = std::stoul(val);
                cfg.port = static_cast<std::uint16_t>(std::max(1ul, std::min(65535ul, u)));
            }
            else if (key == "client_bind")
            {
                cfg.client_bind = val;
            }
            else if (key == "allowed_keys")
            {
                cfg.allowed_keys = val;
            }
            else if (key == "cert")
            {
                cfg.cert = val;
            }
            else if (key == "key")
            {
                cfg.key = val;
            }
            else if (key == "require_tls")
            {
                std::string v = val;
                std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                cfg.require_tls = (v == "true" || v == "yes" || v == "1");
            }
            else if (key == "verbose")
            {
                std::string v = val;
                std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                cfg.verbose = (v == "true" || v == "yes" || v == "1");
            }
            else if (key == "web_port")
            {
                u = std::stoul(val);
                cfg.web_port = static_cast<std::uint16_t>(std::min(65535ul, u));
            }
            else if (key == "web_bind")
            {
                cfg.web_bind = val;
            }
            else if (key == "web_token")
            {
                cfg.web_token = val;
            }
            else if (key == "web_rate_limit_rpm")
            {
                u = std::stoul(val);
                cfg.web_rate_limit_rpm = static_cast<unsigned>(std::min(100000ul, u));
            }
            else if (key == "aggregation_window_days")
            {
                u = std::stoul(val);
                cfg.aggregation_window_days = static_cast<unsigned>(std::max(1ul, std::min(365ul, u)));
            }
            else if (key == "ip_db_path")
            {
                cfg.ip_db_path = val;
            }
            else if (key == "ip_db_url")
            {
                cfg.ip_db_url = val;
            }
            else if (key == "ip_db_update_interval_days")
            {
                u = std::stoul(val);
                cfg.ip_db_update_interval_days =
                    static_cast<unsigned>(std::min<unsigned long>(365u, std::max<unsigned long>(1u, u)));
            }
            else if (key == "ip_db_auto_update")
            {
                std::string v = val;
                std::transform(v.begin(), v.end(), v.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                cfg.ip_db_auto_update = (v == "1" || v == "true" || v == "yes" || v == "on");
            }
            else if (key == "max_recv_buffer_bytes")
            {
                u = std::stoul(val);
                cfg.max_recv_buffer_bytes = static_cast<std::size_t>(std::min(16ul * 1024 * 1024, std::max(4096ul, u)));
            }
            else if (key == "max_flow_entries_per_key")
            {
                u = std::stoul(val);
                cfg.max_flow_entries_per_key = static_cast<std::size_t>(std::min(1000000ul, std::max(100ul, u)));
            }
            else if (key == "max_entity_flow_entries_per_key")
            {
                u = std::stoul(val);
                cfg.max_entity_flow_entries_per_key = static_cast<std::size_t>(std::min(1000000ul, std::max(100ul, u)));
            }
            else if (key == "max_ifaces_per_client")
            {
                u = std::stoul(val);
                cfg.max_ifaces_per_client = static_cast<std::size_t>(std::min(100000ul, std::max(1ul, u)));
            }
            else if (key == "max_entity_lines_in_summary")
            {
                u = std::stoul(val);
                cfg.max_entity_lines_in_summary = static_cast<std::size_t>(std::min(1000000ul, std::max(100ul, u)));
            }
            else if (key == "max_snapshot_entries_for_print")
            {
                u = std::stoul(val);
                cfg.max_snapshot_entries_for_print = static_cast<std::size_t>(std::min(2000000ul, std::max(1000ul, u)));
            }
            else if (key == "max_iface_len")
            {
                u = std::stoul(val);
                cfg.max_iface_len = static_cast<std::size_t>(std::min(256ul, std::max(8ul, u)));
            }
            else if (key == "max_ip_len")
            {
                u = std::stoul(val);
                cfg.max_ip_len = static_cast<std::size_t>(std::min(64ul, std::max(15ul, u)));
            }
            else if (key == "max_concurrent_connections")
            {
                u = std::stoul(val);
                cfg.max_concurrent_connections = static_cast<std::size_t>(std::min(100000ul, std::max(10ul, u)));
            }
            else if (key == "max_connections_per_ip")
            {
                u = std::stoul(val);
                cfg.max_connections_per_ip = static_cast<std::size_t>(std::min(1000ul, std::max(1ul, u)));
            }
            else if (key == "idle_timeout_seconds")
            {
                u = std::stoul(val);
                cfg.idle_timeout_seconds = static_cast<unsigned>(std::min(86400u, std::max(10u, static_cast<unsigned>(u))));
            }
            else if (key == "max_d_lines_per_second_per_connection")
            {
                u = std::stoul(val);
                cfg.max_d_lines_per_second_per_connection = static_cast<unsigned>(std::min(1000000u, std::max(100u, static_cast<unsigned>(u))));
            }
        }
        catch (const std::exception &)
        {
            continue;
        }
    }
    if (recognizedOut) *recognizedOut = recognized;
    return cfg;
}

static SSL_CTX *createServerTLSContext(const std::string &certPath, const std::string &keyPath)
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        return nullptr;
    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    // M1: enforce TLS 1.2+ on the server (matches client minimum).
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_timeout(ctx, static_cast<long>(kMaxSessionSeconds));
    return ctx;
}

// Format bytes into human-readable units (K, M, G, T).
std::string formatBytes(std::uint64_t bytes)
{
    const char *suffixes[] = {"B", "K", "M", "G", "T", "P"};
    double value = static_cast<double>(bytes);
    std::size_t idx = 0;
    while (value >= 1024.0 && idx + 1 < std::size(suffixes))
    {
        value /= 1024.0;
        ++idx;
    }

    std::ostringstream oss;
    if (idx == 0)
    {
        oss << static_cast<std::uint64_t>(value) << suffixes[idx];
    }
    else
    {
        oss.setf(std::ios::fixed);
        oss.precision(1);
        oss << value << suffixes[idx];
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// Web dashboard helpers
// ---------------------------------------------------------------------------

// Returns true if ip (IPv4 or IPv6 string) is in RFC 1918 / loopback / ULA /
// link-local space.  Non-parseable strings return false (reject).
static bool isLanIP(const std::string &ip)
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

// Per-IP sliding-window rate limiter for the web port.
class WebRateLimiter
{
public:
    explicit WebRateLimiter(unsigned rpm) : rpm_(rpm) {}

    // Returns true if the request is allowed, false if over limit.
    bool tryAcquire(const std::string &ip)
    {
        if (rpm_ == 0) return true;
        std::lock_guard<std::mutex> lk(mtx_);
        auto &dq = map_[ip];
        const auto now = std::chrono::steady_clock::now();
        while (!dq.empty() &&
               std::chrono::duration_cast<std::chrono::seconds>(now - dq.front()).count() >= 60)
            dq.pop_front();
        if (dq.size() >= rpm_) return false;
        dq.push_back(now);
        return true;
    }

private:
    unsigned rpm_;
    std::mutex mtx_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> map_;
};

// Escape a string for embedding in a JSON value (returned without surrounding quotes).
static std::string jsonEsc(const std::string &s)
{
    std::string o;
    o.reserve(s.size() + 4);
    for (unsigned char c : s)
    {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 0x20)  ; // drop other control chars
        else                o += static_cast<char>(c);
    }
    return o;
}

static std::string buildSummaryJson(TrafficStats &stats, std::size_t maxEntityLines)
{
    TrafficStats::InterfaceTotals totals;
    TrafficStats::InterfaceFlows flows;
    TrafficStats::InterfaceCountryFlows countryFlows;
    TrafficStats::InterfaceEntityFlows entityFlows;
    TrafficStats::TimePoint windowStart;
    stats.snapshot(totals, flows, countryFlows, entityFlows, &windowStart);

    const auto windowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        windowStart.time_since_epoch()).count();
    const auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string j;
    j.reserve(4096);
    j += "{\n  \"window_start\": ";
    j += std::to_string(windowEpoch);
    j += ",\n  \"generated_at\": ";
    j += std::to_string(nowEpoch);

    // Interfaces
    j += ",\n  \"interfaces\": [";
    bool first = true;
    for (const auto &kv : totals)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(client);
        j += "\",\"iface\":\"";
        j += jsonEsc(iface);
        j += "\",\"packets\":";
        j += std::to_string(kv.second.packets);
        j += ",\"bytes\":";
        j += std::to_string(kv.second.bytes);
        j += '}';
        first = false;
    }
    j += "\n  ]";

    // Entities — collect all rows, sort by bytes descending, truncate
    struct EntityRow
    {
        std::string client, iface, srcEntity, dstEntity;
        std::uint64_t packets{0}, bytes{0};
    };
    std::vector<EntityRow> rows;
    for (const auto &kv : entityFlows)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        for (const auto &ek : kv.second)
            rows.push_back({client, iface, ek.first.src, ek.first.dst,
                            ek.second.packets, ek.second.bytes});
    }
    std::sort(rows.begin(), rows.end(),
              [](const EntityRow &a, const EntityRow &b) { return a.bytes > b.bytes; });
    bool truncated = false;
    if (maxEntityLines > 0 && rows.size() > maxEntityLines)
    {
        rows.resize(maxEntityLines);
        truncated = true;
    }

    j += ",\n  \"entities\": [";
    first = true;
    for (const auto &r : rows)
    {
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(r.client);
        j += "\",\"iface\":\"";
        j += jsonEsc(r.iface);
        j += "\",\"packets\":";
        j += std::to_string(r.packets);
        j += ",\"bytes\":";
        j += std::to_string(r.bytes);
        j += ",\"src_entity\":\"";
        j += jsonEsc(r.srcEntity);
        j += "\",\"dst_entity\":\"";
        j += jsonEsc(r.dstEntity);
        j += "\"}";
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated\": ";
    j += truncated ? "true" : "false";
    j += "\n}\n";
    return j;
}

// Self-contained HTML dashboard served at GET /.
static const char kDashboardHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Monitor</title>
<style>
*{box-sizing:border-box}
body{font-family:monospace;background:#0e0e14;color:#ccc;margin:0;padding:16px}
h1{font-size:1.05em;margin:0 0 4px;color:#7af}
.meta{font-size:0.78em;color:#666;margin-bottom:14px}
.section{color:#7af;font-size:0.82em;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 4px}
table{border-collapse:collapse;width:100%;font-size:0.82em;margin-bottom:4px}
th{background:#161622;color:#888;text-align:left;padding:5px 10px;border-bottom:1px solid #252535;white-space:nowrap}
td{padding:3px 10px;border-bottom:1px solid #1a1a28;white-space:nowrap}
tr:hover td{background:#171726}
.note{font-size:0.75em;color:#666;margin-top:2px}
#status{font-size:0.75em;margin-bottom:10px}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle}
.ok{background:#3a3}
.err{background:#a33}
.trunc{color:#a80;font-style:italic;font-size:0.8em;padding:4px 10px}
</style>
</head>
<body>
<h1>Network Traffic Monitor</h1>
<div id="status"><span id="dot" class="dot ok"></span><span id="smsg">Loading&#8230;</span></div>
<div class="meta">
  Window start: <span id="win">&#8212;</span> &nbsp;|&nbsp;
  Updated: <span id="gen">&#8212;</span> &nbsp;|&nbsp;
  Auto-refresh: 30 s
</div>

<div class="section">Interfaces</div>
<table><thead><tr><th>Client</th><th>Interface</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody id="iface_body"></tbody></table>
<div class="note" id="iface_note"></div>

<div class="section">Entity Flows <span style="color:#555;font-size:0.85em">(sorted by bytes, top results)</span></div>
<table><thead><tr><th>Client</th><th>Interface</th><th>Src Entity</th><th>Dst Entity</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody id="entity_body"></tbody></table>
<div class="note" id="entity_note"></div>

<script>
const POLL_MS=30000;
function fmtB(b){
  if(b<1024)return b+'B';
  if(b<1048576)return(b/1024).toFixed(1)+'K';
  if(b<1073741824)return(b/1048576).toFixed(1)+'M';
  return(b/1073741824).toFixed(2)+'G';
}
function fmtT(ep){return ep?new Date(ep*1000).toLocaleString():'—';}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function row(cells){return'<tr>'+cells.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>';}
async function refresh(){
  try{
    const r=await fetch('/api/summary',{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    document.getElementById('win').textContent=fmtT(d.window_start);
    document.getElementById('gen').textContent=fmtT(d.generated_at);
    const ifaces=d.interfaces||[];
    document.getElementById('iface_body').innerHTML=
      ifaces.length?ifaces.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="4" style="color:#555">No data yet</td></tr>';
    document.getElementById('iface_note').textContent='';
    const ents=d.entities||[];
    document.getElementById('entity_body').innerHTML=
      ents.length?ents.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.src_entity,x.dst_entity,x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="6" style="color:#555">No data yet</td></tr>';
    document.getElementById('entity_note').textContent=
      d.truncated?'Results truncated to server limit.':'';
    setS(true,'OK — '+new Date().toLocaleTimeString());
  }catch(e){setS(false,'Error: '+e.message);}
}
function setS(ok,m){
  document.getElementById('dot').className='dot '+(ok?'ok':'err');
  document.getElementById('smsg').textContent=m;
}
refresh();
setInterval(refresh,POLL_MS);
</script>
</body>
</html>
)HTML";

// Run the HTTPS web dashboard in a background thread.
// Blocks until svr.stop() is called (or cert/key setup fails).
static void webServerThread(httplib::SSLServer &svr,
                            TrafficStats &stats,
                            const ServerConfig &config)
{
    WebRateLimiter rateLimiter(config.web_rate_limit_rpm);

    // Pre-routing: LAN check, rate limit, optional bearer token.
    svr.set_pre_routing_handler(
        [&](const httplib::Request &req, httplib::Response &res) -> httplib::Server::HandlerResponse
        {
            const std::string &ip = req.remote_addr;
            if (!isLanIP(ip))
            {
                res.status = 403;
                res.set_content("{\"error\":\"forbidden: LAN clients only\"}\n",
                                "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (!rateLimiter.tryAcquire(ip))
            {
                res.status = 429;
                res.set_header("Retry-After", "60");
                res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (!config.web_token.empty())
            {
                auto auth = req.get_header_value("Authorization");
                const std::string expected = "Bearer " + config.web_token;
                if (auth != expected)
                {
                    res.status = 401;
                    res.set_header("WWW-Authenticate", "Bearer realm=\"ntm\"");
                    res.set_content("{\"error\":\"unauthorized\"}\n", "application/json");
                    return httplib::Server::HandlerResponse::Handled;
                }
            }
            // Security headers on every response.
            res.set_header("X-Content-Type-Options", "nosniff");
            res.set_header("Content-Security-Policy", "default-src 'self'");
            return httplib::Server::HandlerResponse::Unhandled;
        });

    // GET / — embedded dashboard HTML
    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(kDashboardHtml, "text/html; charset=utf-8");
    });

    // GET /api/summary — JSON snapshot
    svr.Get("/api/summary",
        [&stats, &config](const httplib::Request &, httplib::Response &res) {
            res.set_header("Cache-Control", "no-store");
            res.set_content(buildSummaryJson(stats, config.max_entity_lines_in_summary),
                            "application/json");
        });

    // All other paths → 404
    svr.set_error_handler([](const httplib::Request &, httplib::Response &res) {
        if (res.status == 404)
            res.set_content("{\"error\":\"not found\"}\n", "application/json");
    });

    svr.listen(config.web_bind, static_cast<int>(config.web_port));
}

void connectionThread(int clientFd,
                      std::string peerAddr,
                      std::string clientIp,
                      const AllowedKeysSet &allowedKeys,
                      TrafficStats &stats,
                      IPDataUpdater &ipDataUpdater,
                      std::atomic<std::size_t> &activeConnections,
                      PerIPConnectionLimiter &perIPLimiter,
                      const ServerConfig &config,
                      SSL_CTX *sslCtx,
                      bool requireTlsForThisPort,
                      std::shared_ptr<std::atomic<bool>> doneFlag)
{
    // H1: signal completion to the accept-loop reaper so it can join() and remove the
    // worker entry from the tracking vector. Without this, the vector would grow
    // unboundedly over the server's lifetime (one entry per past connection).
    struct DoneGuard
    {
        std::shared_ptr<std::atomic<bool>> flag;
        ~DoneGuard() { if (flag) flag->store(true, std::memory_order_release); }
    } doneGuard{doneFlag};

    struct Guard
    {
        std::atomic<std::size_t> &n;
        explicit Guard(std::atomic<std::size_t> &n_) : n(n_) {}
        ~Guard() { n--; }
    } guard(activeConnections);

    struct PerIPGuard
    {
        PerIPConnectionLimiter &limiter;
        std::string ip;
        PerIPGuard(PerIPConnectionLimiter &l, std::string i) : limiter(l), ip(std::move(i)) {}
        ~PerIPGuard() { limiter.release(ip); }
    } perIPGuard(perIPLimiter, clientIp);

    // NEW-N1: RAII closer for fd/ssl so any std::exception thrown out of the body
    // doesn't leak the file descriptor or the SSL object. The body sets these to
    // nullptr/-1 on normal close so the destructor is a no-op in the happy path.
    SSL *ssl = nullptr;
    int connFd = clientFd;
    struct ConnCloser
    {
        SSL *&ssl;
        int &fd;
        ~ConnCloser()
        {
            if (ssl)
            {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
            }
            if (fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
        }
    } connCloser{ssl, connFd};

    // NEW-N1: wrap the rest of the body so a bad_alloc / runtime_error inside one
    // connection's processing never propagates out and calls std::terminate.
    try
    {

    if (requireTlsForThisPort && !sslCtx)
    {
        return;
    }

    // M4 + NEW-N5: bound TLS handshake + auth handshake duration. We check the return
    // of setsockopt; on failure we do NOT proceed silently, because both M4 (handshake
    // stall protection) and the read-loop timeout depend on this option taking effect.
    auto setSocketTimeout = [](int fd, unsigned secs) -> bool {
        struct timeval tv;
        tv.tv_sec = static_cast<time_t>(secs);
        tv.tv_usec = 0;
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
            return false;
        if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
            return false;
        return true;
    };
    if (!setSocketTimeout(clientFd, 10))
    {
        serverLog(LogLevel::Err,
                  "ntm-server: cannot set handshake timeout on client fd: %s",
                  std::strerror(errno));
        return;  // ConnCloser cleans up
    }

    if (sslCtx)
    {
        ssl = SSL_new(sslCtx);
        if (!ssl)
            return;
        SSL_set_fd(ssl, clientFd);
        if (SSL_accept(ssl) <= 0)
        {
            ERR_clear_error();
            return;
        }
    }

    const auto sessionStart = std::chrono::steady_clock::now();

    std::string clientId;
    if (!allowedKeys.empty())
    {
        clientId = verifyClientAuth(ssl, clientFd, allowedKeys);
        if (clientId.empty())
        {
            std::uint8_t reject = 0x01;
            writeExact(ssl, clientFd, &reject, 1);
            return;
        }
        std::uint8_t ok = 0x00;
        if (!writeExact(ssl, clientFd, &ok, 1))
            return;
    }
    else
    {
        // M3: in unauthenticated mode key by IP only (not "ip:ephemeral_port") so
        // reconnects from the same host aggregate into the same client ID. With
        // NEW-H1 in place the server will only land here when the operator
        // explicitly opts out of authentication.
        clientId = clientIp.empty() ? peerAddr : clientIp;
    }

    // Idle-recv-block fix: bound the per-recv blocking time so the loop can re-check
    // idle_timeout_seconds and g_running periodically. Without this, a peer that
    // completes auth and then goes silent indefinitely holds a worker thread + slot
    // until the kernel drops the TCP connection (~2h with default keepalives), and
    // server shutdown stalls waiting for those workers to join.
    {
        unsigned pollSecs = config.idle_timeout_seconds;
        if (pollSecs == 0 || pollSecs > 30) pollSecs = 30;
        // NEW-N5: explicitly fail this connection if we cannot install the timeout,
        // because the read loop cannot honor idle_timeout_seconds without it.
        if (!setSocketTimeout(clientFd, pollSecs))
        {
            serverLog(LogLevel::Err,
                      "ntm-server: cannot set read-loop timeout on client fd: %s",
                      std::strerror(errno));
            return;  // ConnCloser cleans up
        }
    }

    std::string buffer;
    buffer.reserve(4096);

    auto lastActivity = std::chrono::steady_clock::now();
    std::int64_t lastDLineSecond = -1;
    std::size_t dLineCountThisSecond = 0;
    // UB-1: per-connection counter of D-lines dropped because the client has
    // exceeded its iface cap. Used to log only on power-of-two crossings so a
    // misbehaving client cannot spam syslog.
    std::uint64_t ifaceRejectedInThisSession = 0;

    char recvBuf[4096];
    while (g_running.load())
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - sessionStart).count();
        if (elapsed < 0)
            elapsed = 0;
        if (static_cast<std::uint64_t>(elapsed) >= kMaxSessionSeconds)
            break;
        auto idleSec = std::chrono::duration_cast<std::chrono::seconds>(now - lastActivity).count();
        if (idleSec >= static_cast<std::chrono::seconds::rep>(config.idle_timeout_seconds))
            break;  // idle timeout

        int n;
        if (ssl)
            n = SSL_read(ssl, recvBuf, sizeof(recvBuf));
        else
            n = static_cast<int>(::recv(clientFd, recvBuf, sizeof(recvBuf), 0));
        if (n <= 0)
        {
            // Distinguish recv timeout (re-check idle / g_running) from real error/close.
            // Both plain recv (returns -1, errno=EAGAIN) and SSL_read (returns -1 with
            // SSL_ERROR_WANT_READ) report "would block" on RCVTIMEO expiry. Anything
            // else is a true close/error and we exit the loop.
            if (n < 0)
            {
                if (!ssl && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                    continue;
                if (ssl)
                {
                    int err = SSL_get_error(ssl, n);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    {
                        ERR_clear_error();
                        continue;
                    }
                    ERR_clear_error();
                }
            }
            break;
        }
        lastActivity = now;
        buffer.append(recvBuf, recvBuf + static_cast<std::size_t>(n));
        if (buffer.size() > config.max_recv_buffer_bytes)
            break;  // disconnect: client sent too much without newline
        std::size_t pos = 0;
        while (true)
        {
            std::size_t nl = buffer.find('\n', pos);
            if (nl == std::string::npos)
                break;
            std::string line = buffer.substr(pos, nl - pos);
            pos = nl + 1;

            if (line.rfind(kDataLinePrefix, 0) == 0)
            {
                PacketMeta meta;
                if (parseDataLine(line.substr(2), meta, config.max_iface_len, config.max_ip_len))
                {
                    auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    if (nowSec != lastDLineSecond)
                    {
                        lastDLineSecond = nowSec;
                        dLineCountThisSecond = 0;
                    }
                    dLineCountThisSecond++;
                    if (dLineCountThisSecond > config.max_d_lines_per_second_per_connection)
                        continue;  // rate limit: drop this line
                    // Grab a fresh snapshot of the resolver per D-line. The
                    // shared_ptr load is mutex-protected but cheap; this gives
                    // long-lived connections the benefit of background DB updates
                    // without restarting. If no DB is loaded yet (e.g. first
                    // startup is still downloading), all lookups return "??".
                    auto resolver = ipDataUpdater.get();
                    std::string srcCountry = resolver ? resolver->countryFor(meta.srcIp)
                                                      : std::string(IPRangeResolver::kUnknownCountry);
                    std::string dstCountry = resolver ? resolver->countryFor(meta.dstIp)
                                                      : std::string(IPRangeResolver::kUnknownCountry);
                    std::string srcEntity  = resolver ? resolver->entityFor(meta.srcIp)
                                                      : std::string(IPRangeResolver::kUnknownEntity);
                    std::string dstEntity  = resolver ? resolver->entityFor(meta.dstIp)
                                                      : std::string(IPRangeResolver::kUnknownEntity);
                    auto addRes = stats.addPacket(clientId, meta.iface, meta.srcIp, meta.dstIp,
                                                  srcCountry, dstCountry, srcEntity, dstEntity, meta.bytes);
                    // UB-1: rate-limit operator visibility into iface-cap rejections.
                    // We log once per power-of-two crossing per connection so a
                    // misbehaving client surfaces but cannot spam syslog.
                    if (addRes == TrafficStats::AddResult::IfaceCapExceeded)
                    {
                        ++ifaceRejectedInThisSession;
                        if ((ifaceRejectedInThisSession & (ifaceRejectedInThisSession - 1)) == 0)
                        {
                            serverLog(LogLevel::Warn,
                                      "ntm-server: client %s exceeded max_ifaces_per_client (%zu) "
                                      "with iface='%s'; %llu lines dropped this session",
                                      clientId.c_str(),
                                      config.max_ifaces_per_client,
                                      meta.iface.c_str(),
                                      static_cast<unsigned long long>(ifaceRejectedInThisSession));
                        }
                    }
                }
            }
        }
        if (pos > 0)
            buffer.erase(0, pos);
    }

    // Normal exit: ConnCloser destructor handles close(connFd) + SSL_free(ssl).

    } // end of try (NEW-N1)
    catch (const std::exception &e)
    {
        serverLog(LogLevel::Err, "ntm-server: connection thread exception caught: %s", e.what());
    }
    catch (...)
    {
        serverLog(LogLevel::Err, "ntm-server: connection thread caught unknown exception");
    }
    // ConnCloser/PerIPGuard/Guard/DoneGuard run here on every path.
}

void statsPrinterThread(TrafficStats &stats, std::size_t maxSnapshotEntriesForPrint)
{
    // NEW-N3: wrap each iteration so a transient bad_alloc (e.g. snapshot copy of
    // very large maps) doesn't kill the entire daemon via std::terminate. We also
    // wrap the outer loop so the thread itself never escapes with an exception.
    while (g_running.load())
    {
        try
        {
        // UE-2 (extra): chunk the inter-iteration sleep so g_running is checked
        // frequently. Previously a 5s sleep_for delayed graceful shutdown by up
        // to 5s after SIGINT/SIGTERM.
        for (int i = 0; i < 20; ++i)
        {
            if (!g_running.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        if (!g_running.load())
            break;

        // H2: in daemon mode we suppress the detailed periodic printout (stderr is /dev/null
        // and syslog is not the right channel for high-frequency multi-line dumps).
        // A separate concise periodic info line via serverLog is emitted instead.
        if (g_daemon.load(std::memory_order_relaxed) && !g_verbose.load(std::memory_order_relaxed))
        {
            TrafficStats::InterfaceTotals totalsQuick;
            TrafficStats::InterfaceFlows flowsQuick;
            TrafficStats::InterfaceCountryFlows countryFlowsQuick;
            TrafficStats::InterfaceEntityFlows entityFlowsQuick;
            stats.snapshot(totalsQuick, flowsQuick, countryFlowsQuick, entityFlowsQuick);
            std::uint64_t totalPackets = 0;
            std::uint64_t totalBytes = 0;
            for (const auto &kv : totalsQuick)
            {
                totalPackets += kv.second.packets;
                totalBytes += kv.second.bytes;
            }
            serverLog(LogLevel::Warn,
                      "ntm-server: stats interfaces=%zu packets=%llu bytes=%s",
                      totalsQuick.size(),
                      static_cast<unsigned long long>(totalPackets),
                      formatBytes(totalBytes).c_str());
            continue;
        }

        TrafficStats::InterfaceTotals totals;
        TrafficStats::InterfaceFlows flows;
        TrafficStats::InterfaceCountryFlows countryFlows;
        TrafficStats::InterfaceEntityFlows entityFlows;
        TrafficStats::TimePoint windowStart;
        stats.snapshot(totals, flows, countryFlows, entityFlows, &windowStart);
        const auto windowEpoch = std::chrono::duration_cast<std::chrono::seconds>(windowStart.time_since_epoch()).count();

        std::size_t totalFlowEntries = 0;
        std::size_t totalEntityEntries = 0;
        for (const auto &kv : flows)
            totalFlowEntries += kv.second.size();
        for (const auto &kv : entityFlows)
            totalEntityEntries += kv.second.size();
        const bool skipDetail = (totalFlowEntries + totalEntityEntries) > maxSnapshotEntriesForPrint;

        // NEW-M2: route detailed verbose stats through one sink so daemon+verbose mode
        // actually reaches syslog. Foreground writes directly to stderr; daemon writes
        // to an ostringstream that is later split by '\n' and emitted as multiple
        // serverLog() calls (each line becomes one syslog entry).
        const bool toSyslog = g_daemon.load(std::memory_order_relaxed);
        std::ostringstream daemonBuf;
        std::ostream &out = toSyslog
            ? static_cast<std::ostream &>(daemonBuf)
            : static_cast<std::ostream &>(std::cerr);

        if (skipDetail)
            out << "(snapshot has " << totalFlowEntries + totalEntityEntries
                << " flow+entity entries; omitting per-interface detail)\n";

        // Group by client and interface: key format is "client|iface".
        struct IfaceEntry
        {
            std::string iface;
            Counter total;
        };
        std::unordered_map<std::string, std::vector<IfaceEntry>> byClient;

        for (const auto &kv : totals)
        {
            const auto &key = kv.first;
            const auto &c = kv.second;
            auto sep = key.find('|');
            std::string client = sep == std::string::npos ? std::string{} : key.substr(0, sep);
            std::string iface = sep == std::string::npos ? key : key.substr(sep + 1);

            byClient[client].push_back(IfaceEntry{std::move(iface), c});
        }

        out << "==== Aggregated traffic (rolling window; oldest day at " << windowEpoch << " epoch sec) ====\n";
        for (auto &clientPair : byClient)
        {
            const std::string &client = clientPair.first;
            auto &interfaces = clientPair.second;

            out << "Client " << (client.empty() ? "<unknown>" : client) << ":\n";
            for (const auto &entry : interfaces)
            {
                const auto &iface = entry.iface;
                const auto &c = entry.total;
                const std::string key = client + "|" + iface;

                out << "  Interface " << iface
                    << "  packets=" << c.packets
                    << "  bytes=" << formatBytes(c.bytes) << '\n';

                if (skipDetail)
                    continue;

                // Show top N flows by bytes for this client+interface.
                auto itFlows = flows.find(key);
                if (itFlows != flows.end() && !itFlows->second.empty())
                {
                    std::vector<std::pair<FlowKey, FlowStats>> v;
                    v.reserve(itFlows->second.size());
                    for (const auto &fk : itFlows->second)
                    {
                        v.emplace_back(fk.first, fk.second);
                    }
                    std::sort(v.begin(), v.end(),
                              [](const auto &a, const auto &b) {
                                  return a.second.bytes > b.second.bytes;
                              });
                    std::size_t limit = std::min<std::size_t>(v.size(), 5);
                    out << "    Top flows:\n";
                    for (std::size_t i = 0; i < limit; ++i)
                    {
                        const auto &fk = v[i].first;
                        const auto &fc = v[i].second;
                        double avgIntervalSec = 0.0;
                        if (fc.packets > 1 && fc.lastSeenSec > fc.firstSeenSec && fc.firstSeenSec >= 0)
                        {
                            const std::int64_t span = fc.lastSeenSec - fc.firstSeenSec;
                            if (span > 0)
                                avgIntervalSec = static_cast<double>(span) / static_cast<double>(fc.packets - 1);
                        }
                        out << "      " << fk.src << " -> " << fk.dst
                            << "  packets=" << fc.packets
                            << "  bytes=" << formatBytes(fc.bytes);
                        if (fc.firstSeenSec >= 0 && fc.lastSeenSec >= 0)
                        {
                            out << "  first_seen=" << fc.firstSeenSec
                                << "  last_seen=" << fc.lastSeenSec;
                            if (avgIntervalSec > 0.0)
                                out << "  approx_interval_s=" << avgIntervalSec;
                        }
                        out << '\n';
                    }
                }
                // Top entity (ASN/org) flows for this client+interface.
                auto itEntity = entityFlows.find(key);
                if (itEntity != entityFlows.end() && !itEntity->second.empty())
                {
                    std::vector<std::pair<FlowKey, Counter>> ev;
                    ev.reserve(itEntity->second.size());
                    for (const auto &ek : itEntity->second)
                        ev.emplace_back(ek.first, ek.second);
                    std::sort(ev.begin(), ev.end(),
                              [](const auto &a, const auto &b) { return a.second.bytes > b.second.bytes; });
                    std::size_t elim = std::min<std::size_t>(ev.size(), 5);
                    out << "    Top entity flows:\n";
                    for (std::size_t i = 0; i < elim; ++i)
                    {
                        out << "      " << ev[i].first.src << " -> " << ev[i].first.dst
                            << "  packets=" << ev[i].second.packets
                            << "  bytes=" << formatBytes(ev[i].second.bytes) << '\n';
                    }
                }
            }
        }
        out << "============================\n";

        // Flush captured text to syslog as one line per entry.
        if (toSyslog)
        {
            const std::string text = daemonBuf.str();
            std::size_t start = 0;
            while (start < text.size())
            {
                std::size_t nl = text.find('\n', start);
                std::size_t end = (nl == std::string::npos) ? text.size() : nl;
                if (end > start)
                {
                    // Cap individual syslog line length to keep within typical syslog limits.
                    constexpr std::size_t kMaxLineLen = 900;
                    std::size_t len = end - start;
                    if (len > kMaxLineLen) len = kMaxLineLen;
                    // We only enter this block in daemon+verbose mode, so Info passes.
                    serverLog(LogLevel::Info, "%.*s",
                              static_cast<int>(len), text.c_str() + start);
                }
                if (nl == std::string::npos) break;
                start = nl + 1;
            }
        }
        } // end of try (NEW-N3)
        catch (const std::exception &e)
        {
            serverLog(LogLevel::Err, "ntm-server: stats printer iteration exception: %s", e.what());
            // UE-7: brief back-off after a caught exception to avoid syslog flooding
            // if the failure mode is persistent (e.g. recurring bad_alloc).
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        catch (...)
        {
            serverLog(LogLevel::Err, "ntm-server: stats printer iteration caught unknown exception");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void keyboardWatcherThread()
{
    // UE-2: poll stdin with a small timeout so the watcher checks g_running
    // periodically. Previously this thread blocked in std::cin.get() until EOF
    // or a key press, which caused graceful shutdown (Ctrl+C in foreground) to
    // hang at join() until the user typed something or closed the terminal.
    // NEW-N1: defensive try/catch so any unexpected exception cannot kill the daemon.
    try
    {
        constexpr int kPollIntervalMs = 250;
        while (g_running.load())
        {
            struct pollfd pfd;
            pfd.fd = STDIN_FILENO;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int pr = ::poll(&pfd, 1, kPollIntervalMs);
            if (pr == 0)
                continue;  // timeout: re-check g_running
            if (pr < 0)
            {
                if (errno == EINTR) continue;
                // Unexpected poll error: log and back off briefly, but don't exit
                // the thread because main() is waiting to join us.
                serverLog(LogLevel::Warn, "ntm-server: stdin poll failed: %s",
                          std::strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }
            if (pfd.revents & (POLLHUP | POLLNVAL))
                break;  // stdin closed or invalid
            if (!(pfd.revents & POLLIN))
                continue;
            char c = 0;
            ssize_t n = ::read(STDIN_FILENO, &c, 1);
            if (n <= 0)
                break;  // EOF or error: stop watching
            if (c == 'q' || c == 'Q')
            {
                serverLog(LogLevel::Warn, "ntm-server: received 'q' on stdin, shutting down...");
                g_running.store(false);
                break;
            }
        }
    }
    catch (...)
    {
        serverLog(LogLevel::Err, "ntm-server: keyboard watcher thread caught exception");
    }
}

int runServer(std::uint16_t port, bool daemonMode, bool verbose,
              const std::string &allowedKeysPath,
              const std::string &certPath, const std::string &keyPath,
              const ServerConfig &config, bool requireTls)
{
    // H2: open syslog before daemonize() because daemonize closes stderr.
    g_verbose.store(verbose, std::memory_order_relaxed);
    if (daemonMode)
    {
        openlog("ntm-server", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        g_daemon.store(true, std::memory_order_relaxed);
    }
    if (daemonMode)
    {
        daemonize();
    }

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);
    std::signal(SIGPIPE, SIG_IGN);

    SSL_CTX *sslCtx = nullptr;
    if (!certPath.empty() && !keyPath.empty())
    {
        sslCtx = createServerTLSContext(certPath, keyPath);
        if (!sslCtx)
        {
            serverLog(LogLevel::Err, "ntm-server: failed to load TLS cert/key from %s / %s",
                      certPath.c_str(), keyPath.c_str());
            if (!g_daemon.load()) ERR_print_errors_fp(stderr);
            return 1;
        }
        serverLog(LogLevel::Warn, "ntm-server: TLS enabled (session max %u hours)",
                  static_cast<unsigned>(kMaxSessionSeconds / 3600));
    }
    else
    {
        serverLog(LogLevel::Warn, "ntm-server: no TLS (--cert/--key not set); connection not encrypted");
    }
    if (requireTls && !sslCtx)
    {
        serverLog(LogLevel::Err, "ntm-server: TLS required but TLS not configured; use --cert and --key");
        return 1;
    }
    if (requireTls)
        serverLog(LogLevel::Warn, "ntm-server: TLS required (plain TCP rejected)");

    // NEW-H1: fail-closed authentication.
    // If the operator configured an allowed-keys file, refuse to start with zero
    // valid keys loaded. Without this, a typo in the path or a corrupted file would
    // silently downgrade the server to "no auth" because connectionThread treats an
    // empty allow-list as "accept anyone".
    AllowedKeysSet allowedKeys = loadAllowedKeys(allowedKeysPath);
    if (!allowedKeysPath.empty())
    {
        if (allowedKeys.empty())
        {
            serverLog(LogLevel::Err,
                      "ntm-server: --allowed-keys/allowed_keys is set to '%s' but loaded 0 valid keys; "
                      "refusing to start in fail-open mode (fix the file or unset the option).",
                      allowedKeysPath.c_str());
            if (sslCtx) SSL_CTX_free(sslCtx);
            return 1;
        }
        serverLog(LogLevel::Warn, "ntm-server: loaded %zu allowed client key(s)", allowedKeys.size());
    }
    else
    {
        serverLog(LogLevel::Warn,
                  "ntm-server: NO CLIENT AUTHENTICATION configured (allowed_keys not set); "
                  "any reachable host can submit data");
    }

    TrafficStats stats(config.aggregation_window_days,
                       config.max_flow_entries_per_key,
                       config.max_entity_flow_entries_per_key,
                       config.max_ifaces_per_client);

    // IP-to-country/ASN resolver + background auto-updater. Replaces both the
    // old GeoIPResolver and EntityResolver. Source: iptoasn.com (CC0).
    IPDataUpdater::Config ipCfg;
    ipCfg.path = config.ip_db_path;
    ipCfg.url  = config.ip_db_url;
    ipCfg.refresh_days = config.ip_db_update_interval_days;
    ipCfg.auto_update  = config.ip_db_auto_update;
    IPDataUpdater ipDataUpdater(ipCfg, [](int prio, const std::string &msg) {
        LogLevel lvl = LogLevel::Info;
        if (prio == 3) lvl = LogLevel::Err;
        else if (prio == 4) lvl = LogLevel::Warn;
        else if (prio == 6) lvl = LogLevel::Info;
        serverLog(lvl, "%s", msg.c_str());
    });
    // Try to load the existing on-disk file synchronously so lookups work from
    // line 1. If it's missing or stale, the updater's background thread will
    // download a fresh copy shortly after start().
    ipDataUpdater.loadInitial();
    ipDataUpdater.start();

    serverLog(LogLevel::Warn, "ntm-server: aggregation rolling window %u day(s); limits from config",
              config.aggregation_window_days);
    serverLog(LogLevel::Info,
              "ntm-server: IP database path=%s url=%s refresh_days=%u auto_update=%s",
              config.ip_db_path.c_str(), config.ip_db_url.c_str(),
              config.ip_db_update_interval_days,
              config.ip_db_auto_update ? "yes" : "no");

    auto createListenSocket = [](const std::string &bindAddr, std::uint16_t p) -> int
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        int opt = 1;
        // UE-4: SO_REUSEADDR failure is not fatal but should be visible. Without
        // it, a quick restart after Ctrl+C can hit TIME_WAIT and bind() will fail;
        // operators benefit from knowing if the option didn't take effect.
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
        {
            serverLog(LogLevel::Warn,
                      "ntm-server: setsockopt(SO_REUSEADDR) on %s:%u failed: %s",
                      bindAddr.empty() ? "0.0.0.0" : bindAddr.c_str(), p,
                      std::strerror(errno));
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (bindAddr.empty())
        {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else
        {
            if (::inet_pton(AF_INET, bindAddr.c_str(), &addr.sin_addr) != 1)
            {
                ::close(fd);
                errno = EINVAL;
                return -1;
            }
        }
        addr.sin_port = htons(p);
        if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            ::close(fd);
            return -1;
        }
        if (listen(fd, 16) < 0)
        {
            ::close(fd);
            return -1;
        }
        return fd;
    };

    int listenFdClient = createListenSocket(config.client_bind, port);
    if (listenFdClient < 0)
    {
        serverLog(LogLevel::Err, "ntm-server: listen(client port %u) failed: %s",
                  static_cast<unsigned>(port), std::strerror(errno));
        return 1;
    }

    serverLog(LogLevel::Warn, "ntm-server listening on client port %u (%s)",
              static_cast<unsigned>(port), daemonMode ? "daemon mode" : "foreground mode");

    // Start HTTPS web dashboard if web_port > 0 and TLS cert/key are configured.
    std::unique_ptr<httplib::SSLServer> webSvr;
    std::thread webThread;
    if (config.web_port > 0)
    {
        if (certPath.empty() || keyPath.empty())
        {
            serverLog(LogLevel::Warn,
                      "ntm-server: web_port=%u configured but --cert/--key not set; "
                      "web dashboard disabled (HTTPS requires a certificate)",
                      static_cast<unsigned>(config.web_port));
        }
        else
        {
            try
            {
                webSvr = std::make_unique<httplib::SSLServer>(certPath.c_str(), keyPath.c_str());
                if (!webSvr->is_valid())
                {
                    serverLog(LogLevel::Err,
                              "ntm-server: failed to initialise HTTPS server (bad cert/key at %s / %s)",
                              certPath.c_str(), keyPath.c_str());
                    webSvr.reset();
                }
                else
                {
                    webThread = std::thread(webServerThread,
                                            std::ref(*webSvr),
                                            std::ref(stats),
                                            std::cref(config));
                    serverLog(LogLevel::Warn,
                              "ntm-server: HTTPS web dashboard on %s:%u (LAN-only, rate-limit %u rpm)",
                              config.web_bind.c_str(),
                              static_cast<unsigned>(config.web_port),
                              config.web_rate_limit_rpm);
                    if (!config.web_token.empty())
                        serverLog(LogLevel::Warn, "ntm-server: web dashboard bearer token auth enabled");
                    else
                        serverLog(LogLevel::Warn,
                                  "ntm-server: web dashboard has no bearer token; "
                                  "access restricted to LAN IPs only");
                }
            }
            catch (const std::exception &e)
            {
                serverLog(LogLevel::Err, "ntm-server: web server init failed: %s", e.what());
                webSvr.reset();
            }
        }
    }
    else
    {
        serverLog(LogLevel::Warn, "ntm-server: web dashboard disabled (web_port=0)");
    }

    std::thread printer(statsPrinterThread, std::ref(stats), config.max_snapshot_entries_for_print);
    std::thread keyWatcher;
    if (!daemonMode)
    {
        keyWatcher = std::thread(keyboardWatcherThread);
    }

    // H1: self-pruning worker tracking. Each spawned thread sets its `done` flag
    // when it exits; the accept loop joins+erases finished entries each iteration so
    // the vector size never exceeds the number of currently-live connections.
    struct WorkerEntry
    {
        std::thread t;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<WorkerEntry> workers;
    workers.reserve(config.max_concurrent_connections);
    auto reapFinishedWorkers = [&]() {
        for (auto it = workers.begin(); it != workers.end(); )
        {
            if (it->done && it->done->load(std::memory_order_acquire))
            {
                if (it->t.joinable())
                    it->t.join();
                it = workers.erase(it);
            }
            else
            {
                ++it;
            }
        }
    };

    std::atomic<std::size_t> activeClientConnections{0};
    PerIPConnectionLimiter perIPLimiterClient(config.max_connections_per_ip);

    while (g_running.load())
    {
        pollfd fds[1]{};
        fds[0].fd = listenFdClient;
        fds[0].events = POLLIN;
        int pr = ::poll(fds, 1, 1000);
        if (pr < 0)
        {
            if (errno == EINTR)
                continue;
            serverLog(LogLevel::Err, "ntm-server: poll failed: %s", std::strerror(errno));
            break;
        }
        // H1: reap any worker threads that finished since the last iteration.
        reapFinishedWorkers();
        if (pr == 0)
            continue;

        if (!(fds[0].revents & POLLIN))
            continue;
        int acceptFd = listenFdClient;

        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientFd = ::accept(acceptFd, reinterpret_cast<sockaddr *>(&clientAddr), &len);
        if (clientFd < 0)
        {
            // UE-1: triage accept() errors. EINTR / ECONNABORTED / EPROTO are
            // transient and POSIX specifically calls them out as retry-the-call
            // conditions. EMFILE / ENFILE are fd exhaustion: the daemon should
            // not exit (operators frequently see EMFILE transiently under load),
            // we back off briefly and continue. Anything else is treated as fatal.
            const int e = errno;
            if (e == EINTR || e == ECONNABORTED || e == EPROTO)
                continue;
            if (e == EAGAIN || e == EWOULDBLOCK)
                continue;
            if (e == EMFILE || e == ENFILE)
            {
                serverLog(LogLevel::Warn,
                          "ntm-server: accept failed (fd exhaustion): %s; backing off 100ms",
                          std::strerror(e));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            serverLog(LogLevel::Err, "ntm-server: accept failed (fatal): %s", std::strerror(e));
            break;
        }

        auto &activeConnections = activeClientConnections;
        const std::size_t maxConn = config.max_concurrent_connections;

        if (activeConnections.load(std::memory_order_relaxed) >= maxConn)
        {
            ::close(clientFd);
            serverLog(LogLevel::Warn, "ntm-server: connection limit reached (%zu), rejecting", maxConn);
            continue;
        }

        char addrBuf[INET_ADDRSTRLEN]{};
        const char *ntop = ::inet_ntop(AF_INET, &clientAddr.sin_addr, addrBuf, sizeof(addrBuf));
        // UE-3: if inet_ntop fails (essentially impossible for AF_INET, but POSIX
        // permits it), refuse the connection rather than silently bypass the per-IP
        // limiter. An empty IP string would also short-circuit tryAcquire("") to
        // true, defeating the cap. Synthesize a safe fallback identifier from the
        // raw sin_addr so the per-IP cap still works, and log loudly.
        std::string clientIpStr;
        if (ntop)
        {
            clientIpStr.assign(addrBuf);
        }
        else
        {
            // Fall back to the raw u32 in network byte order as a string so the
            // per-IP limiter sees a distinct, deterministic key per peer.
            std::uint32_t raw = clientAddr.sin_addr.s_addr;
            char fb[32];
            std::snprintf(fb, sizeof(fb), "raw:%u", static_cast<unsigned>(raw));
            clientIpStr.assign(fb);
            serverLog(LogLevel::Warn,
                      "ntm-server: inet_ntop failed for accepted client (errno=%d %s); "
                      "using synthetic key '%s' for per-IP limit",
                      errno, std::strerror(errno), clientIpStr.c_str());
        }
        std::string peerAddr = clientIpStr + ":" + std::to_string(ntohs(clientAddr.sin_port));

        auto &perIPLimiter = perIPLimiterClient;
        if (!perIPLimiter.tryAcquire(clientIpStr))
        {
            ::close(clientFd);
            serverLog(LogLevel::Warn, "ntm-server: per-IP connection limit reached for %s, rejecting",
                      clientIpStr.empty() ? "<unknown>" : clientIpStr.c_str());
            continue;
        }
        activeConnections++;

        // NEW-N2: spawn the worker exception-safely. If make_shared throws bad_alloc
        // or std::thread() throws system_error (e.g. pthread EAGAIN), we must release
        // everything acquired above (clientFd, per-IP slot, activeConnections counter).
        // Otherwise a single resource-pressure event permanently leaks those slots.
        // workers.push_back is bounded by reserve(max_concurrent_connections +
        // max_concurrent_monitor_connections), so realistic OOM there is impossible.
        try
        {
            std::shared_ptr<std::atomic<bool>> doneFlag =
                std::make_shared<std::atomic<bool>>(false);
            std::thread t(connectionThread,
                          clientFd,
                          peerAddr,
                          clientIpStr,
                          std::cref(allowedKeys),
                          std::ref(stats),
                          std::ref(ipDataUpdater),
                          std::ref(activeConnections),
                          std::ref(perIPLimiter),
                          std::cref(config),
                          sslCtx,
                          requireTls,
                          doneFlag);
            // From here on, t is a live joinable thread. The only ops left are
            // noexcept (shared_ptr move, thread move, vector push into reserved
            // storage). If a future change makes push_back throwing again, detach
            // the thread inside that branch to avoid std::terminate on temporary
            // destruction.
            workers.push_back(WorkerEntry{std::move(t), std::move(doneFlag)});
        }
        catch (const std::exception &e)
        {
            ::close(clientFd);
            perIPLimiter.release(clientIpStr);
            activeConnections--;
            serverLog(LogLevel::Err,
                      "ntm-server: worker spawn failed (%s); slot released, dropping connection",
                      e.what());
        }
        catch (...)
        {
            ::close(clientFd);
            perIPLimiter.release(clientIpStr);
            activeConnections--;
            serverLog(LogLevel::Err,
                      "ntm-server: worker spawn failed (unknown exception); slot released, dropping connection");
        }
    }

    ::close(listenFdClient);
    g_running.store(false);

    // Stop the web server (SSLServer::stop() is thread-safe).
    if (webSvr)
    {
        webSvr->stop();
        if (webThread.joinable())
            webThread.join();
    }

    for (auto &w : workers)
    {
        if (w.t.joinable())
            w.t.join();
    }
    workers.clear();

    // Stop the IP data updater BEFORE freeing SSL_CTX. The updater holds a
    // libcurl handle (uses OpenSSL internally on most distros). Stopping it
    // first guarantees it can't be in the middle of an SSL_read when SSL_CTX
    // is torn down.
    ipDataUpdater.stop();

    // Free SSL_CTX after all workers have released their SSL objects so we don't
    // tear down crypto state while a worker is still using it.
    if (sslCtx)
        SSL_CTX_free(sslCtx);

    if (printer.joinable())
        printer.join();

    if (keyWatcher.joinable())
        keyWatcher.join();

    if (g_daemon.load(std::memory_order_relaxed))
        closelog();

    return 0;
}

} // namespace ntm

// H3: parse a TCP port from a CLI string; print error and return false on bad input.
// Catches std::stoi exceptions so a typo like "--port abc" never aborts the process.
static bool parsePortArg(const char *flag, const char *valStr, std::uint16_t &out)
{
    try
    {
        std::size_t consumed = 0;
        long n = std::stol(valStr, &consumed);
        if (consumed != std::strlen(valStr) || n < 1 || n > 65535)
            throw std::out_of_range("port out of range");
        out = static_cast<std::uint16_t>(n);
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "ntm-server: invalid value for " << flag << ": '" << valStr
                  << "' (expected 1-65535): " << e.what() << "\n";
        return false;
    }
}

int main(int argc, char *argv[])
{
    bool daemonMode = false;
    bool verbose = false;
    std::string configPath;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        if (arg == "--config" && i + 1 < argc)
        {
            configPath = argv[++i];
            break;
        }
        if (arg == "--help" || arg == "-h")
        {
            std::cout <<
                "Usage: ntm-server [--daemon] [--verbose] [--require-tls] [--port N]\n"
                "                  [--allowed-keys FILE] [--cert PEM] [--key PEM]\n"
                "                  [--web-port N] [--web-bind IP] [--web-token TOKEN]\n"
                "                  [--config FILE]\n"
                "  Options can be set in config file (key=value); command-line overrides config.\n"
                "  Web dashboard (HTTPS) requires --cert and --key.\n";
            return 0;
        }
    }

    // M7: load config exactly once and fail loudly if --config was given but the
    // file could not be opened (avoids silently using defaults on a typo).
    // NEW-N8: also warn if the file opened but contained zero recognized keys.
    bool configOk = true;
    std::size_t recognizedKeys = 0;
    ntm::ServerConfig config = ntm::loadServerConfig(configPath, &configOk, &recognizedKeys);
    if (!configPath.empty() && !configOk)
    {
        std::cerr << "ntm-server: cannot open --config file: '" << configPath
                  << "' (refusing to fall back to defaults)\n";
        return 1;
    }
    if (!configPath.empty() && recognizedKeys == 0)
    {
        std::cerr << "ntm-server: WARNING: --config file '" << configPath
                  << "' contained no recognized keys; running with built-in defaults\n";
    }
    std::uint16_t port = config.port;
    std::string allowedKeysPath = config.allowed_keys;
    std::string certPath = config.cert;
    std::string keyPath = config.key;
    bool requireTls = config.require_tls;
    if (!verbose) verbose = config.verbose;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        if (arg == "--daemon")
            daemonMode = true;
        else if (arg == "--verbose")
            verbose = true;
        else if (arg == "--require-tls")
            requireTls = true;
        else if (arg == "--port" && i + 1 < argc)
        {
            if (!parsePortArg("--port", argv[++i], port))
                return 1;
        }
        else if (arg == "--allowed-keys" && i + 1 < argc)
            allowedKeysPath = argv[++i];
        else if (arg == "--cert" && i + 1 < argc)
            certPath = argv[++i];
        else if (arg == "--key" && i + 1 < argc)
            keyPath = argv[++i];
        else if (arg == "--web-port" && i + 1 < argc)
        {
            if (!parsePortArg("--web-port", argv[++i], config.web_port))
                return 1;
        }
        else if (arg == "--web-bind" && i + 1 < argc)
            config.web_bind = argv[++i];
        else if (arg == "--web-token" && i + 1 < argc)
            config.web_token = argv[++i];
        else if (arg == "--config" && i + 1 < argc)
            ++i;
        else if (arg == "--help" || arg == "-h")
            ;
        else
        {
            std::cerr << "ntm-server: unknown or incomplete argument: '" << arg << "'\n";
            return 1;
        }
    }

    return ntm::runServer(port, daemonMode, verbose, allowedKeysPath,
                          certPath, keyPath, config, requireTls);
}

