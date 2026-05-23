// web_dashboard.cpp — HTTPS dashboard: HTTP routes, JSON API, embedded HTML/CSS/JS.
// Edit this file to change the web UI or add API endpoints.
// The only dependency on server internals is TrafficStats::snapshot() via ntm_types.hpp.

#include "web_dashboard.hpp"
#include "proto_client_server.hpp"
#include "version.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <openssl/crypto.h>   // CRYPTO_memcmp
#include <openssl/evp.h>      // EVP_sha256 (manifest SHA-256)
#include <openssl/rand.h>     // RAND_bytes

namespace ntm
{

// ---------------------------------------------------------------------------
// Demo server state (App Store review — port kDemoPort)
// ---------------------------------------------------------------------------

// Operator-controlled enable flag. Default: false (disabled on startup).
// Toggled via POST /api/admin/demo on the main web server.
static std::atomic<bool> g_demoEnabled{false};

// Start epoch of the current demo session (0 = no session active).
// Set on first request; auto-resets after kDemoSessionSec so a fresh
// reviewer always gets a full 15-minute window.
static std::atomic<std::int64_t> g_demoSessionStart{0};

// In-memory store of active demo tokens: token → expiry epoch (seconds).
static std::mutex g_demoTokensMtx;
static std::unordered_map<std::string, std::int64_t> g_demoTokens;

static std::string generateDemoToken()
{
    unsigned char buf[16];
    RAND_bytes(buf, sizeof(buf));
    std::string tok = "demo_";
    tok.reserve(5 + 32);
    for (auto b : buf)
    {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02x", b);
        tok += hex;
    }
    return tok;
}

// Returns true if token is a valid, unexpired demo token. Lazily prunes expired entries.
static bool checkDemoToken(const std::string &token)
{
    if (token.size() < 5 || token.substr(0, 5) != "demo_") return false;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lk(g_demoTokensMtx);
    auto it = g_demoTokens.find(token);
    if (it == g_demoTokens.end()) return false;
    if (now >= it->second) { g_demoTokens.erase(it); return false; }
    return true;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Admin proof tokens — short-lived cookie issued after admin password verification.
// Separate from the WebAuthn passkey session: any passkey user can view the
// dashboard, but only someone who also knows the admin password can enter /admin.
// ---------------------------------------------------------------------------
static constexpr std::int64_t kAdminProofTokenSec = 1800; // 30 minutes
static std::mutex g_adminProofMtx;
static std::unordered_map<std::string, std::int64_t> g_adminProofTokens; // token → expiry

static std::string generateAdminProofToken()
{
    unsigned char buf[16];
    RAND_bytes(buf, sizeof(buf));
    std::string tok = "ntm_ap_";
    tok.reserve(7 + 32);
    for (auto b : buf) { char h[3]; std::snprintf(h, sizeof(h), "%02x", b); tok += h; }
    return tok;
}

static bool checkAdminProofToken(const std::string &token)
{
    if (token.size() < 7 || token.substr(0, 7) != "ntm_ap_") return false;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lk(g_adminProofMtx);
    auto it = g_adminProofTokens.find(token);
    if (it == g_adminProofTokens.end()) return false;
    if (now >= it->second) { g_adminProofTokens.erase(it); return false; }
    return true;
}

// ---------------------------------------------------------------------------
// Update manifest (scanned from update_dir on demand)
// ---------------------------------------------------------------------------
struct UpdateManifestEntry {
    std::string platform;   // e.g. "linux-amd64"
    std::string version;    // e.g. "1.9.0"
    std::string filename;   // bare filename, no path
    std::string sha256hex;  // 64 lowercase hex digits
};
static std::mutex g_manifestMtx;
static std::vector<UpdateManifestEntry> g_manifest;

// Per-client force-update set: 64-hex pubkeys flagged for next check.
static std::mutex g_forceMtx;
static std::unordered_set<std::string> g_forceUpdateClients;

// Builds /api/summary JSON for the demo server.
// ---------------------------------------------------------------------------
// Update manifest helpers
// ---------------------------------------------------------------------------

static int semverCmp(const std::string &a, const std::string &b)
{
    auto parse = [](const std::string &v) -> std::array<int,3> {
        std::array<int,3> r{0,0,0};
        int part = 0;
        for (unsigned char c : v) {
            if (c == '.' && part < 2) { ++part; }
            else if (c >= '0' && c <= '9') { r[part] = r[part] * 10 + (c - '0'); }
        }
        return r;
    };
    auto pa = parse(a), pb = parse(b);
    for (int i = 0; i < 3; ++i) {
        if (pa[i] < pb[i]) return -1;
        if (pa[i] > pb[i]) return  1;
    }
    return 0;
}

static std::string sha256FileHex(const std::string &path)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return "";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { std::fclose(f); return ""; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    unsigned char buf[65536];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);
    std::fclose(f);
    unsigned char hash[32];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(hex[(hash[i] >> 4) & 0xf]);
        out.push_back(hex[hash[i] & 0xf]);
    }
    return out;
}

static std::string hexToRaw32(const std::string &hex)
{
    if (hex.size() != 64) return "";
    std::string raw;
    raw.reserve(32);
    for (std::size_t i = 0; i < 64; i += 2) {
        auto h = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = h(hex[i]), lo = h(hex[i+1]);
        if (hi < 0 || lo < 0) return "";
        raw.push_back(static_cast<char>((hi << 4) | lo));
    }
    return raw;
}

// Scan update_dir for ntm-client binaries, compute SHA-256, update g_manifest.
// Keeps only the highest version per platform.
static std::size_t scanUpdateDir(const std::string &dir)
{
    namespace fs = std::filesystem;
    std::vector<UpdateManifestEntry> entries;
    std::error_code ec;
    for (auto &entry : fs::directory_iterator(dir, ec))
    {
        if (!entry.is_regular_file(ec)) continue;
        std::string name = entry.path().filename().string();
        const std::string prefix = "ntm-client-";
        if (name.size() <= prefix.size()) continue;
        if (name.substr(0, prefix.size()) != prefix) continue;
        std::string rest = name.substr(prefix.size());
        // Strip .exe
        if (rest.size() > 4 && rest.substr(rest.size() - 4) == ".exe")
            rest = rest.substr(0, rest.size() - 4);
        // rest = "<platform>-<version>", platform has exactly one '-' (e.g. linux-amd64)
        // so we have at least two '-' total: split at second-to-last '-'
        auto lastHyp = rest.rfind('-');
        if (lastHyp == std::string::npos || lastHyp == 0) continue;
        std::string plat = rest.substr(0, lastHyp);
        std::string ver  = rest.substr(lastHyp + 1);
        if (plat.empty() || ver.empty()) continue;
        bool validVer = true;
        for (unsigned char c : ver)
            if (c != '.' && (c < '0' || c > '9')) { validVer = false; break; }
        if (!validVer) continue;
        std::string sha = sha256FileHex(entry.path().string());
        if (sha.empty()) continue;
        entries.push_back({plat, ver, name, sha});
    }

    // Keep highest version per platform.
    std::vector<UpdateManifestEntry> best;
    for (auto &e : entries)
    {
        auto it = std::find_if(best.begin(), best.end(),
                               [&](const UpdateManifestEntry &b){ return b.platform == e.platform; });
        if (it == best.end())
            best.push_back(e);
        else if (semverCmp(e.version, it->version) > 0)
            *it = e;
    }

    {
        std::lock_guard<std::mutex> lk(g_manifestMtx);
        g_manifest = std::move(best);
        return g_manifest.size();
    }
}

// Schema MUST mirror buildSummaryJson() — update whenever that function changes.
// CLAUDE.md "Demo mock data" rule enforces this.
static std::string buildDemoSummaryJson()
{
    const auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Establish or reset demo session.
    std::int64_t sessionStart = g_demoSessionStart.load(std::memory_order_relaxed);
    if (sessionStart == 0 || (nowEpoch - sessionStart) >= kDemoSessionSec)
    {
        g_demoSessionStart.store(nowEpoch, std::memory_order_relaxed);
        sessionStart = nowEpoch;
    }

    // Tick advances every health interval — gives numbers a live-data feel.
    const std::int64_t tick = (nowEpoch / static_cast<std::int64_t>(kHealthIntervalSec)) % 500;

    const std::int64_t windowStart   = nowEpoch - 7 * 86400;
    const std::int64_t demoExpiresAt = sessionStart + kDemoSessionSec;

    // Byte totals used for overhead percentage.
    const std::int64_t totalBytes = 3142857600LL + 1258291200LL + 5905580032LL
                                  + tick * (52480 + 14336 + 81920);
    const std::int64_t ohBytes    = 157286400LL + 168689664LL + tick * 1024;
    const std::int64_t pct100     = (ohBytes * 10000LL) / totalBytes;
    std::string ohPct = std::to_string(pct100 / 100) + ".";
    if ((pct100 % 100) < 10) ohPct += "0";
    ohPct += std::to_string(pct100 % 100);

    std::string j;
    j.reserve(4096);

    // Root — mirrors buildSummaryJson() root section exactly.
    j += "{\n  \"api_version\": ";              j += std::to_string(kApiVersion);
    j += ",\n  \"server_version\": \"";         j += kServerVersion; j += "\"";
    j += ",\n  \"server_wire_proto_version\": "; j += std::to_string(kWireProtoVersion);
    j += ",\n  \"demo\": true";
    j += ",\n  \"demo_expires_at\": ";           j += std::to_string(demoExpiresAt);
    j += ",\n  \"demo_server_enabled\": true";
    j += ",\n  \"window_start\": ";              j += std::to_string(windowStart);
    j += ",\n  \"generated_at\": ";              j += std::to_string(nowEpoch);

    // interfaces
    j += ",\n  \"interfaces\": ["
         "\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"packets\":"; j += std::to_string(3247891 + tick * 87);
    j += ",\"bytes\":";  j += std::to_string(3142857600LL + tick * 52480); j += "}";
    j += ",\n    {\"client\":\"iPhone-15\",\"iface\":\"en0\","
         "\"packets\":"; j += std::to_string(891203 + tick * 23);
    j += ",\"bytes\":";  j += std::to_string(1258291200LL + tick * 14336); j += "}";
    j += ",\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"packets\":"; j += std::to_string(4892341 + tick * 134);
    j += ",\"bytes\":";  j += std::to_string(5905580032LL + tick * 81920); j += "}";
    j += "\n  ]";

    // entities (non-overhead, sorted by bytes desc)
    j += ",\n  \"entities\": ["
         "\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"src_entity\":\"Desktop-PC\",\"dst_entity\":\"Netflix Inc.\","
         "\"packets\":"; j += std::to_string(2108344 + tick * 60);
    j += ",\"bytes\":"; j += std::to_string(2251799814LL + tick * 65536); j += "}";
    j += ",\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"MacBook-Air\",\"dst_entity\":\"Google LLC\","
         "\"packets\":"; j += std::to_string(1289341 + tick * 34);
    j += ",\"bytes\":"; j += std::to_string(1288490189LL + tick * 40960); j += "}";
    j += ",\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"src_entity\":\"Desktop-PC\",\"dst_entity\":\"Cloudflare Inc.\","
         "\"packets\":"; j += std::to_string(980241 + tick * 27);
    j += ",\"bytes\":"; j += std::to_string(1027604480LL + tick * 32768); j += "}";
    j += ",\n    {\"client\":\"iPhone-15\",\"iface\":\"en0\","
         "\"src_entity\":\"iPhone-15\",\"dst_entity\":\"Apple Inc.\","
         "\"packets\":"; j += std::to_string(541203 + tick * 15);
    j += ",\"bytes\":"; j += std::to_string(472446402LL + tick * 8192); j += "}";
    j += ",\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"MacBook-Air\",\"dst_entity\":\"Amazon.com Inc.\","
         "\"packets\":"; j += std::to_string(334891 + tick * 9);
    j += ",\"bytes\":"; j += std::to_string(335544320LL + tick * 10240); j += "}";
    j += ",\n    {\"client\":\"iPhone-15\",\"iface\":\"en0\","
         "\"src_entity\":\"iPhone-15\",\"dst_entity\":\"Akamai Technologies Inc.\","
         "\"packets\":"; j += std::to_string(218452 + tick * 6);
    j += ",\"bytes\":"; j += std::to_string(188743680LL + tick * 4096); j += "}";
    j += "\n  ]";
    j += ",\n  \"truncated\": false";

    // entities_internet (same rows as entities — all demo flows are WAN)
    j += ",\n  \"entities_internet\": ["
         "\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"src_entity\":\"Desktop-PC\",\"dst_entity\":\"Netflix Inc.\","
         "\"packets\":"; j += std::to_string(2108344 + tick * 60);
    j += ",\"bytes\":"; j += std::to_string(2251799814LL + tick * 65536); j += "}";
    j += ",\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"MacBook-Air\",\"dst_entity\":\"Google LLC\","
         "\"packets\":"; j += std::to_string(1289341 + tick * 34);
    j += ",\"bytes\":"; j += std::to_string(1288490189LL + tick * 40960); j += "}";
    j += ",\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"src_entity\":\"Desktop-PC\",\"dst_entity\":\"Cloudflare Inc.\","
         "\"packets\":"; j += std::to_string(980241 + tick * 27);
    j += ",\"bytes\":"; j += std::to_string(1027604480LL + tick * 32768); j += "}";
    j += ",\n    {\"client\":\"iPhone-15\",\"iface\":\"en0\","
         "\"src_entity\":\"iPhone-15\",\"dst_entity\":\"Apple Inc.\","
         "\"packets\":"; j += std::to_string(541203 + tick * 15);
    j += ",\"bytes\":"; j += std::to_string(472446402LL + tick * 8192); j += "}";
    j += ",\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"MacBook-Air\",\"dst_entity\":\"Amazon.com Inc.\","
         "\"packets\":"; j += std::to_string(334891 + tick * 9);
    j += ",\"bytes\":"; j += std::to_string(335544320LL + tick * 10240); j += "}";
    j += ",\n    {\"client\":\"iPhone-15\",\"iface\":\"en0\","
         "\"src_entity\":\"iPhone-15\",\"dst_entity\":\"Akamai Technologies Inc.\","
         "\"packets\":"; j += std::to_string(218452 + tick * 6);
    j += ",\"bytes\":"; j += std::to_string(188743680LL + tick * 4096); j += "}";
    j += "\n  ]";
    j += ",\n  \"truncated_internet\": false";

    // entities_local (demo shows a small LAN-to-LAN file share)
    j += ",\n  \"entities_local\": ["
         "\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"Local Devices\",\"dst_entity\":\"Local Devices\","
         "\"packets\":"; j += std::to_string(12481 + tick);
    j += ",\"bytes\":"; j += std::to_string(41943040LL + tick * 512); j += "}";
    j += "\n  ]";
    j += ",\n  \"truncated_local\": false";
    {
        const std::int64_t locBytes = 41943040LL + tick * 512;
        const std::int64_t locPct100 = (locBytes * 10000LL) / totalBytes;
        std::string locPct = std::to_string(locPct100 / 100) + ".";
        if ((locPct100 % 100) < 10) locPct += "0";
        locPct += std::to_string(locPct100 % 100);
        j += ",\n  \"local_summary\": {\"packets\":";
        j += std::to_string(12481 + tick);
        j += ",\"bytes\":"; j += std::to_string(locBytes);
        j += ",\"pct_of_total_bytes\":\""; j += locPct; j += "\"}";
    }

    // overhead_entities
    j += ",\n  \"overhead_entities\": ["
         "\n    {\"client\":\"MacBook-Air\",\"iface\":\"en0\","
         "\"src_entity\":\"MacBook-Air\",\"dst_entity\":\"Hetzner Online GmbH\","
         "\"packets\":"; j += std::to_string(48291 + tick * 2);
    j += ",\"bytes\":"; j += std::to_string(157286400LL + tick * 512); j += "}";
    j += ",\n    {\"client\":\"Desktop-PC\",\"iface\":\"eth0\","
         "\"src_entity\":\"Desktop-PC\",\"dst_entity\":\"Hetzner Online GmbH\","
         "\"packets\":"; j += std::to_string(51832 + tick * 2);
    j += ",\"bytes\":"; j += std::to_string(168689664LL + tick * 512); j += "}";
    j += "\n  ]";
    j += ",\n  \"truncated_overhead\": false";

    // overhead_summary
    j += ",\n  \"overhead_summary\": {\"packets\":";
    j += std::to_string(100123 + tick * 4);
    j += ",\"bytes\":"; j += std::to_string(ohBytes);
    j += ",\"pct_of_total_bytes\":\""; j += ohPct; j += "\"}";

    // entities_lan
    j += ",\n  \"entities_lan\": ["
         "\n    {\"ip\":\"192.168.1.1\",\"reported_by\":\"\","
         "\"out_packets\":"; j += std::to_string(150341 + tick * 4);
    j += ",\"out_bytes\":"; j += std::to_string(54525952LL + tick * 1024);
    j += ",\"in_packets\":"; j += std::to_string(892103 + tick * 24);
    j += ",\"in_bytes\":"; j += std::to_string(1153433600LL + tick * 16384); j += "}";
    j += ",\n    {\"ip\":\"192.168.1.100\",\"reported_by\":\"\","
         "\"out_packets\":"; j += std::to_string(45123 + tick);
    j += ",\"out_bytes\":"; j += std::to_string(8388608LL + tick * 256);
    j += ",\"in_packets\":"; j += std::to_string(210891 + tick * 6);
    j += ",\"in_bytes\":"; j += std::to_string(398458880LL + tick * 4096); j += "}";
    j += "\n  ]";
    j += ",\n  \"truncated_lan\": false";

    // client_health
    j += ",\n  \"client_health\": ["
         "\n    {\"client\":\"MacBook-Air\","
         "\"client_id\":\"0000000000000000000000000000000000000000000000000000000000000001\","
         "\"version\":\"1.8.1\",\"platform\":\"linux-amd64\","
         "\"pcap_recv\":"; j += std::to_string(2847281 + tick * 76);
    j += ",\"pcap_drop\":0,\"pcap_drop_pct\":\"0.00\","
         "\"buf_drop\":0,\"buf_drop_pct\":\"0.00\","
         "\"reported_at\":"; j += std::to_string(nowEpoch - 12);
    j += ",\"stale\":false,\"wire_proto_version\":1,\"wire_proto_ok\":true}";
    j += ",\n    {\"client\":\"iPhone-15\","
         "\"client_id\":\"0000000000000000000000000000000000000000000000000000000000000002\","
         "\"version\":\"1.0.0\",\"platform\":\"\","
         "\"pcap_recv\":"; j += std::to_string(741083 + tick * 20);
    j += ",\"pcap_drop\":0,\"pcap_drop_pct\":\"0.00\","
         "\"buf_drop\":0,\"buf_drop_pct\":\"0.00\","
         "\"reported_at\":"; j += std::to_string(nowEpoch - 8);
    j += ",\"stale\":false,\"wire_proto_version\":1,\"wire_proto_ok\":true}";
    j += ",\n    {\"client\":\"Desktop-PC\","
         "\"client_id\":\"0000000000000000000000000000000000000000000000000000000000000003\","
         "\"version\":\"1.8.1\",\"platform\":\"windows-amd64\","
         "\"pcap_recv\":"; j += std::to_string(4192841 + tick * 112);
    j += ",\"pcap_drop\":0,\"pcap_drop_pct\":\"0.00\","
         "\"buf_drop\":0,\"buf_drop_pct\":\"0.00\","
         "\"reported_at\":"; j += std::to_string(nowEpoch - 5);
    j += ",\"stale\":false,\"wire_proto_version\":1,\"wire_proto_ok\":true}";
    j += "\n  ]";

    j += ",\n  \"proto_rejected_clients\": []";
    j += ",\n  \"update_manifest\": []";
    j += "\n}\n";
    return j;
}

// ---------------------------------------------------------------------------
// Per-IP sliding-window rate limiter
// ---------------------------------------------------------------------------

class WebRateLimiter
{
public:
    explicit WebRateLimiter(unsigned rpm) : rpm_(rpm) {}

    bool tryAcquire(const std::string &ip)
    {
        if (rpm_ == 0) return true;
        std::lock_guard<std::mutex> lk(mtx_);
        const auto now = std::chrono::steady_clock::now();

        // Periodic sweep: erase entries whose 60 s window has fully drained so
        // the map cannot grow unboundedly with one entry per distinct source IP
        // ever seen. O(n) every 256 calls — negligible for a LAN-only endpoint.
        if (((++ops_) & 0xFFu) == 0)
        {
            for (auto it = map_.begin(); it != map_.end(); )
            {
                auto &q = it->second;
                while (!q.empty() &&
                       std::chrono::duration_cast<std::chrono::seconds>(now - q.front()).count() >= 60)
                    q.pop_front();
                it = q.empty() ? map_.erase(it) : std::next(it);
            }
        }

        auto &dq = map_[ip];
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
    std::uint64_t ops_{0};
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> map_;
};

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// Escape a string for embedding in a JSON value (without surrounding quotes).
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

// Extract a string field value from a flat JSON object body.
// Handles \" and \\ escapes. Returns empty string on parse failure.
static std::string jsonGetString(const std::string &json, const std::string &key)
{
    const std::string needle = "\"" + key + "\"";
    std::size_t pos = 0;
    while (pos < json.size())
    {
        auto found = json.find(needle, pos);
        if (found == std::string::npos) return {};
        pos = found + needle.size();
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;
        if (pos >= json.size() || json[pos] != ':') continue; // false match inside a value
        ++pos;
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;
        if (pos >= json.size() || json[pos] != '"') return {};
        ++pos;
        std::string result;
        while (pos < json.size())
        {
            char c = json[pos++];
            if (c == '"') return result;
            if (c == '\\' && pos < json.size())
            {
                char e = json[pos++];
                switch (e) {
                    case '"':  result += '"';  break;
                    case '\\': result += '\\'; break;
                    case '/':  result += '/';  break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    default:   result += e;    break;
                }
            }
            else result += c;
        }
        return {};
    }
    return {};
}

// Returns the real client IP. When the connection arrives from config.trusted_proxy
// (e.g. cloudflared on 127.0.0.1), the real IP is read from CF-Connecting-IP first,
// then the first entry of X-Forwarded-For. Only exact-match proxy IPs are trusted,
// which prevents header injection from direct (non-proxied) connections.
static std::string effectiveClientIP(const httplib::Request &req, const WebConfig &config)
{
    if (config.trusted_proxy.empty() || req.remote_addr != config.trusted_proxy)
        return req.remote_addr;
    auto cfIP = req.get_header_value("CF-Connecting-IP");
    if (!cfIP.empty()) return cfIP;
    auto xff = req.get_header_value("X-Forwarded-For");
    if (!xff.empty())
    {
        auto comma = xff.find(',');
        return comma == std::string::npos ? xff : xff.substr(0, comma);
    }
    return req.remote_addr;
}

// Extract a named cookie value from the Cookie header.
static std::string cookieFromRequest(const httplib::Request &req, const std::string &name)
{
    auto cookie = req.get_header_value("Cookie");
    const std::string prefix = name + "=";
    auto pos = cookie.find(prefix);
    if (pos == std::string::npos) return {};
    auto start = pos + prefix.size();
    auto end   = cookie.find(';', start);
    return cookie.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// Extract session token from Authorization: Bearer header or ntm_session cookie.
static std::string sessionFromRequest(const httplib::Request &req)
{
    auto auth = req.get_header_value("Authorization");
    if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ")
        return auth.substr(7);
    auto cookie = req.get_header_value("Cookie");
    const std::string prefix = "ntm_session=";
    auto pos = cookie.find(prefix);
    if (pos != std::string::npos)
    {
        auto start = pos + prefix.size();
        auto end   = cookie.find(';', start);
        return cookie.substr(start, end == std::string::npos ? std::string::npos : end - start);
    }
    return {};
}

// ---------------------------------------------------------------------------
// Summary JSON builder
// ---------------------------------------------------------------------------

static std::string buildSummaryJson(TrafficStats &stats, std::size_t maxEntityLines,
                                    const std::unordered_map<std::string, std::string> &nicknames,
                                    const std::shared_ptr<ClientRegistry> &registry,
                                    const std::shared_ptr<MonitoringIpSet> &serverIps,
                                    const std::shared_ptr<MonitoringIpSet> &dashboardIps)
{
    TrafficStats::InterfaceTotals totals;
    TrafficStats::InterfaceFlows flows;
    TrafficStats::InterfaceCountryFlows countryFlows;
    TrafficStats::InterfaceEntityFlows entityFlows;
    TrafficStats::TimePoint windowStart;
    stats.snapshot(totals, flows, countryFlows, entityFlows, &windowStart);

    const auto serverIpSnap   = serverIps   ? serverIps->ipSet()   : std::unordered_set<std::string>{};
    const auto dashboardIpSnap = dashboardIps ? dashboardIps->ipSet() : std::unordered_set<std::string>{};

    // Display name for any stored identifier: 64-char hex pubkey → nickname (or hex);
    // raw LAN IP → "Local Devices" (main tab); ASN entity string → as-is.
    // Entity strings are resolved to stable hex client IDs at ingest time, so no
    // IP→display registry lookup is needed here.
    auto isHexClientId = [](const std::string &s) -> bool {
        if (s.size() != 64) return false;
        for (char c : s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    };
    // Detects external-IP-scoped LAN keys produced at ingest time: "@[{scope}]:{ip}".
    // scope is the client's public WAN IP (or "null" when unreachable).
    // Clients behind the same NAT share the same scope → their unknown devices merge.
    auto parseReporterScoped = [](const std::string &s,
                                   std::string *scope = nullptr,
                                   std::string *lanIp = nullptr) -> bool {
        if (s.size() < 5 || s[0] != '@' || s[1] != '[') return false;
        auto cb = s.find(']', 2);
        if (cb == std::string::npos || cb + 1 >= s.size() || s[cb + 1] != ':') return false;
        if (scope) *scope  = s.substr(2, cb - 2);
        if (lanIp) *lanIp  = s.substr(cb + 2);
        return true;
    };
    auto displayClient = [&nicknames, &isHexClientId](const std::string &s) -> std::string {
        if (isHexClientId(s)) {
            auto it = nicknames.find(s);
            return it != nicknames.end() ? it->second : s;
        }
        return s;
    };
    // Returns true when a flow endpoint is the server itself or a connected dashboard client.
    // Known ntm-client hex IDs are intentionally NOT treated as infra endpoints here: using
    // them would make every packet on the ntm-client machine (regular browsing, downloads, …)
    // appear as overhead, because the client registers its own LAN IP and all its traffic has
    // the hex clientId as one endpoint.  The wire-protocol connection is caught via the server
    // IP check (server is always the other endpoint).  The only remaining gap is when the
    // server is reached via an external IP whose entity string is an ASN name rather than a
    // raw IP; that case is documented as a known limitation for cloud-hosted servers.
    auto isInfraEndpoint = [&](const std::string &key) -> bool {
        std::string lanIp;
        if (parseReporterScoped(key, nullptr, &lanIp))
            return serverIpSnap.count(lanIp) > 0 || dashboardIpSnap.count(lanIp) > 0;
        return serverIpSnap.count(key) > 0 || dashboardIpSnap.count(key) > 0;
    };

    auto fmtPct = [](std::uint64_t num, std::uint64_t denom) -> std::string {
        if (denom == 0) return "0.00";
        std::uint64_t pct100 = (num * 10000ULL) / denom;
        std::string s = std::to_string(pct100 / 100);
        s += '.';
        std::uint64_t frac = pct100 % 100;
        if (frac < 10) s += '0';
        s += std::to_string(frac);
        return s;
    };

    auto resolveEntityMain = [&](const std::string &s) -> std::string {
        if (isHexClientId(s)) {
            auto it = nicknames.find(s);
            return it != nicknames.end() ? it->second : s;
        }
        // External-IP-scoped unknown LAN device: "@[{scope}]:{ip}"
        // scope is the shared WAN IP; "null" means no internet was reachable.
        std::string scope;
        if (parseReporterScoped(s, &scope)) {
            if (scope == "null") return "LAN (no internet)";
            return "LAN (" + scope + ")";
        }
        if (isLanIP(s)) return "Local Devices";
        return s;
    };

    const auto windowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        windowStart.time_since_epoch()).count();
    const auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string j;
    j.reserve(8192);
    j += "{\n  \"api_version\": ";
    j += std::to_string(kApiVersion);
    j += ",\n  \"server_version\": \"";
    j += kServerVersion;
    j += "\"";
    j += ",\n  \"server_wire_proto_version\": ";
    j += std::to_string(kWireProtoVersion);
    j += ",\n  \"demo_server_enabled\": ";
    j += g_demoEnabled.load(std::memory_order_relaxed) ? "true" : "false";
    j += ",\n  \"window_start\": ";
    j += std::to_string(windowEpoch);
    j += ",\n  \"generated_at\": ";
    j += std::to_string(nowEpoch);

    // Interfaces — unchanged
    j += ",\n  \"interfaces\": [";
    bool first = true;
    for (const auto &kv : totals)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(displayClient(client));   // hex → nickname (or hex if no nickname)
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

    // Entity Summary: group raw stored entities by resolved display labels, merge, sort.
    struct SummaryKey
    {
        std::string client, iface, src, dst;
        bool operator==(const SummaryKey &o) const noexcept
        {
            return client == o.client && iface == o.iface && src == o.src && dst == o.dst;
        }
    };
    struct SummaryKeyHash
    {
        std::size_t operator()(const SummaryKey &k) const noexcept
        {
            std::hash<std::string> h;
            return ((h(k.client) * 2654435761u) ^ (h(k.iface) * 40503u))
                 ^ ((h(k.src)    * 1315423911u) ^ h(k.dst));
        }
    };
    std::unordered_map<SummaryKey, Counter, SummaryKeyHash> summaryGroups;   // legacy union (kept for compat)
    std::unordered_map<SummaryKey, Counter, SummaryKeyHash> internetGroups; // WAN flows
    std::unordered_map<SummaryKey, Counter, SummaryKeyHash> localGroups;    // LAN-only flows
    std::unordered_map<SummaryKey, Counter, SummaryKeyHash> overheadGroups;

    std::uint64_t totalAllBytes  = 0;
    std::uint64_t overheadBytes  = 0;
    std::uint64_t overheadPkts   = 0;
    std::uint64_t localBytes     = 0;
    std::uint64_t localPkts      = 0;

    // LAN Detail: per unidentified-LAN-IP in/out totals, aggregated across all clients/ifaces.
    struct LanStats { std::uint64_t outPkts{0}, outBytes{0}, inPkts{0}, inBytes{0}; };
    std::unordered_map<std::string, LanStats> lanMap;

    for (const auto &kv : entityFlows)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        const std::string &dispCli = displayClient(client);

        for (const auto &ek : kv.second)
        {
            const std::string &storedSrc = ek.first.src;
            const std::string &storedDst = ek.first.dst;
            const std::uint64_t pkts  = ek.second.packets;
            const std::uint64_t bytes = ek.second.bytes;

            totalAllBytes += bytes;

            // Overhead: touches the server or a dashboard client, or two ntm-client agents
            // talking directly to each other (edge case; caught by the hex-ID pair check).
            const bool isOvhd = isInfraEndpoint(storedSrc) || isInfraEndpoint(storedDst)
                                 || (isHexClientId(storedSrc) && isHexClientId(storedDst));

            if (isOvhd)
            {
                overheadPkts  += pkts;
                overheadBytes += bytes;
                auto &og = overheadGroups[{dispCli, iface,
                                           resolveEntityMain(storedSrc),
                                           resolveEntityMain(storedDst)}];
                og.packets += pkts;
                og.bytes   += bytes;
            }
            else
            {
                const SummaryKey rk{dispCli, iface,
                                    resolveEntityMain(storedSrc),
                                    resolveEntityMain(storedDst)};
                auto &sg = summaryGroups[rk];
                sg.packets += pkts;
                sg.bytes   += bytes;

                // Classify as local (both endpoints private) or internet (at least one public).
                const bool srcLocal = parseReporterScoped(storedSrc) || isLanIP(storedSrc)
                                      || isHexClientId(storedSrc);
                const bool dstLocal = parseReporterScoped(storedDst) || isLanIP(storedDst)
                                      || isHexClientId(storedDst);
                if (srcLocal && dstLocal)
                {
                    auto &lg = localGroups[rk];
                    lg.packets += pkts;
                    lg.bytes   += bytes;
                    localPkts  += pkts;
                    localBytes += bytes;
                }
                else
                {
                    auto &ig = internetGroups[rk];
                    ig.packets += pkts;
                    ig.bytes   += bytes;
                }

                // Accumulate per-IP in/out for unidentified LAN IPs.
                // Known client IPs are stored as hex IDs at ingest time.
                // Unknown LAN devices use the reporter-scoped "@hex:ip" key format;
                // legacy raw LAN IPs (if any) are also included for backwards compatibility.
                const bool srcUnident = parseReporterScoped(storedSrc) || isLanIP(storedSrc);
                const bool dstUnident = parseReporterScoped(storedDst) || isLanIP(storedDst);
                if (srcUnident) { auto &ls = lanMap[storedSrc]; ls.outPkts += pkts; ls.outBytes += bytes; }
                if (dstUnident) { auto &ls = lanMap[storedDst]; ls.inPkts  += pkts; ls.inBytes  += bytes; }
            }
        }
    }

    // Sort Entity Summary rows by bytes descending, truncate.
    struct SummaryRow { std::string client, iface, src, dst; std::uint64_t packets{0}, bytes{0}; };
    std::vector<SummaryRow> summaryRows;
    summaryRows.reserve(summaryGroups.size());
    for (const auto &kv : summaryGroups)
        summaryRows.push_back({kv.first.client, kv.first.iface,
                               kv.first.src,    kv.first.dst,
                               kv.second.packets, kv.second.bytes});
    std::sort(summaryRows.begin(), summaryRows.end(),
              [](const SummaryRow &a, const SummaryRow &b) { return a.bytes > b.bytes; });
    bool truncated = false;
    if (maxEntityLines > 0 && summaryRows.size() > maxEntityLines)
    {
        summaryRows.resize(maxEntityLines);
        truncated = true;
    }

    // Sort internet rows by bytes descending, truncate.
    std::vector<SummaryRow> internetRows;
    internetRows.reserve(internetGroups.size());
    for (const auto &kv : internetGroups)
        internetRows.push_back({kv.first.client, kv.first.iface,
                                kv.first.src,    kv.first.dst,
                                kv.second.packets, kv.second.bytes});
    std::sort(internetRows.begin(), internetRows.end(),
              [](const SummaryRow &a, const SummaryRow &b) { return a.bytes > b.bytes; });
    bool truncatedInternet = false;
    if (maxEntityLines > 0 && internetRows.size() > maxEntityLines)
    {
        internetRows.resize(maxEntityLines);
        truncatedInternet = true;
    }

    // Sort local rows by bytes descending, truncate.
    std::vector<SummaryRow> localRows;
    localRows.reserve(localGroups.size());
    for (const auto &kv : localGroups)
        localRows.push_back({kv.first.client, kv.first.iface,
                             kv.first.src,    kv.first.dst,
                             kv.second.packets, kv.second.bytes});
    std::sort(localRows.begin(), localRows.end(),
              [](const SummaryRow &a, const SummaryRow &b) { return a.bytes > b.bytes; });
    bool truncatedLocal = false;
    if (maxEntityLines > 0 && localRows.size() > maxEntityLines)
    {
        localRows.resize(maxEntityLines);
        truncatedLocal = true;
    }

    // Sort overhead rows by bytes descending, truncate.
    std::vector<SummaryRow> overheadRows;
    overheadRows.reserve(overheadGroups.size());
    for (const auto &kv : overheadGroups)
        overheadRows.push_back({kv.first.client, kv.first.iface,
                                kv.first.src,    kv.first.dst,
                                kv.second.packets, kv.second.bytes});
    std::sort(overheadRows.begin(), overheadRows.end(),
              [](const SummaryRow &a, const SummaryRow &b) { return a.bytes > b.bytes; });
    bool truncatedOverhead = false;
    if (maxEntityLines > 0 && overheadRows.size() > maxEntityLines)
    {
        overheadRows.resize(maxEntityLines);
        truncatedOverhead = true;
    }

    // Sort LAN Detail rows by total bytes descending, truncate.
    struct LanRow { std::string ip; std::uint64_t outPkts{0}, outBytes{0}, inPkts{0}, inBytes{0}; };
    std::vector<LanRow> lanRows;
    lanRows.reserve(lanMap.size());
    for (const auto &kv : lanMap)
        lanRows.push_back({kv.first,
                           kv.second.outPkts, kv.second.outBytes,
                           kv.second.inPkts,  kv.second.inBytes});
    std::sort(lanRows.begin(), lanRows.end(),
              [](const LanRow &a, const LanRow &b) {
                  return (a.outBytes + a.inBytes) > (b.outBytes + b.inBytes);
              });
    bool truncatedLan = false;
    if (maxEntityLines > 0 && lanRows.size() > maxEntityLines)
    {
        lanRows.resize(maxEntityLines);
        truncatedLan = true;
    }

    // Emit Entity Summary
    j += ",\n  \"entities\": [";
    first = true;
    for (const auto &r : summaryRows)
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
        j += jsonEsc(r.src);
        j += "\",\"dst_entity\":\"";
        j += jsonEsc(r.dst);
        j += "\"}";
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated\": ";
    j += truncated ? "true" : "false";

    // Emit Internet Entity rows (WAN — at least one public endpoint)
    auto emitEntityRows = [&](const std::vector<SummaryRow> &rows) {
        bool f = true;
        for (const auto &r : rows)
        {
            if (!f) j += ',';
            j += "\n    {\"client\":\""; j += jsonEsc(r.client);
            j += "\",\"iface\":\"";      j += jsonEsc(r.iface);
            j += "\",\"packets\":";      j += std::to_string(r.packets);
            j += ",\"bytes\":";          j += std::to_string(r.bytes);
            j += ",\"src_entity\":\"";   j += jsonEsc(r.src);
            j += "\",\"dst_entity\":\""; j += jsonEsc(r.dst);
            j += "\"}";
            f = false;
        }
    };
    j += ",\n  \"entities_internet\": [";
    emitEntityRows(internetRows);
    j += "\n  ]";
    j += ",\n  \"truncated_internet\": ";
    j += truncatedInternet ? "true" : "false";

    // Emit Local Entity rows (both endpoints private/LAN)
    j += ",\n  \"entities_local\": [";
    emitEntityRows(localRows);
    j += "\n  ]";
    j += ",\n  \"truncated_local\": ";
    j += truncatedLocal ? "true" : "false";
    j += ",\n  \"local_summary\": {\"packets\":";
    j += std::to_string(localPkts);
    j += ",\"bytes\":";
    j += std::to_string(localBytes);
    j += ",\"pct_of_total_bytes\":\"";
    j += fmtPct(localBytes, totalAllBytes);
    j += "\"}";

    // Emit Overhead Entity rows
    j += ",\n  \"overhead_entities\": [";
    first = true;
    for (const auto &r : overheadRows)
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
        j += jsonEsc(r.src);
        j += "\",\"dst_entity\":\"";
        j += jsonEsc(r.dst);
        j += "\"}";
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated_overhead\": ";
    j += truncatedOverhead ? "true" : "false";

    // Emit overhead summary
    j += ",\n  \"overhead_summary\": {";
    j += "\"packets\":";
    j += std::to_string(overheadPkts);
    j += ",\"bytes\":";
    j += std::to_string(overheadBytes);
    j += ",\"pct_of_total_bytes\":\"";
    j += fmtPct(overheadBytes, totalAllBytes);
    j += "\"}";

    // Emit LAN Detail
    j += ",\n  \"entities_lan\": [";
    first = true;
    for (const auto &r : lanRows)
    {
        if (!first) j += ',';
        // Parse external-IP-scoped key "@[{scope}]:{ip}" if present; fall back to raw IP.
        std::string displayIp, reportedBy, scope;
        if (parseReporterScoped(r.ip, &scope, &displayIp)) {
            reportedBy = (scope == "null") ? "no internet" : scope;
        } else {
            displayIp  = r.ip;
            reportedBy = "";
        }
        j += "\n    {\"ip\":\"";
        j += jsonEsc(displayIp);
        j += "\",\"reported_by\":\"";
        j += jsonEsc(reportedBy);
        j += "\",\"out_packets\":";
        j += std::to_string(r.outPkts);
        j += ",\"out_bytes\":";
        j += std::to_string(r.outBytes);
        j += ",\"in_packets\":";
        j += std::to_string(r.inPkts);
        j += ",\"in_bytes\":";
        j += std::to_string(r.inBytes);
        j += '}';
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated_lan\": ";
    j += truncatedLan ? "true" : "false";

    // Emit client health stats (snapshotted from shared registry under mutex).
    j += ",\n  \"client_health\": [";
    first = true;
    if (registry)
    {
        struct HealthSnap { std::string clientId; ClientHealthStats hs; };
        std::vector<HealthSnap> healthSnaps;
        {
            std::lock_guard<std::mutex> lk(registry->mtx);
            for (const auto &kv : registry->clientHealth)
                healthSnaps.push_back({kv.first, kv.second});
        }
        const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (const auto &snap : healthSnaps)
        {
            const auto &hs = snap.hs;
            const std::uint64_t pcapTotal = hs.pcapRecv + hs.pcapDrop;
            const bool stale = (hs.reportedAtSec >= 0) &&
                               ((nowSec - hs.reportedAtSec) > 90);
            if (!first) j += ',';
            j += "\n    {\"client\":\"";
            j += jsonEsc(displayClient(snap.clientId));
            j += "\",\"client_id\":\"";
            j += jsonEsc(snap.clientId);
            j += "\",\"version\":\"";
            j += jsonEsc(hs.version.empty() ? "?" : hs.version);
            j += "\",\"platform\":\"";
            j += jsonEsc(hs.platform);
            j += "\",\"pcap_recv\":";
            j += std::to_string(hs.pcapRecv);
            j += ",\"pcap_drop\":";
            j += std::to_string(hs.pcapDrop);
            j += ",\"pcap_drop_pct\":\"";
            j += fmtPct(hs.pcapDrop, pcapTotal);
            j += "\",\"buf_drop\":";
            j += std::to_string(hs.bufDrop);
            j += ",\"buf_drop_pct\":\"";
            j += fmtPct(hs.bufDrop, hs.pcapRecv);
            j += "\",\"reported_at\":";
            j += std::to_string(hs.reportedAtSec);
            j += ",\"stale\":";
            j += stale ? "true" : "false";
            if (hs.wireProtoVersion > 0)
            {
                j += ",\"wire_proto_version\":";
                j += std::to_string(hs.wireProtoVersion);
                j += ",\"wire_proto_ok\":";
                j += (hs.wireProtoVersion == kWireProtoVersion) ? "true" : "false";
            }
            j += '}';
            first = false;
        }
    }
    j += "\n  ]";

    // Proto-rejected clients (auth version mismatch attempts, capped at 20).
    j += ",\n  \"proto_rejected_clients\": [";
    if (registry)
    {
        std::vector<ProtoRejectionRecord> rejSnap;
        {
            std::lock_guard<std::mutex> lk(registry->mtx);
            rejSnap.assign(registry->protoRejections.begin(), registry->protoRejections.end());
        }
        bool rejFirst = true;
        for (const auto &r : rejSnap)
        {
            if (!rejFirst) j += ',';
            j += "\n    {\"peer_ip\":\"";
            j += jsonEsc(r.peerIp);
            j += "\",\"attempted_auth_version\":";
            j += std::to_string(r.attemptedVersion);
            j += ",\"at\":";
            j += std::to_string(r.atSec);
            j += '}';
            rejFirst = false;
        }
    }
    j += "\n  ]";

    // update_manifest — snapshot of g_manifest for the admin page.
    j += ",\n  \"update_manifest\": [";
    {
        std::lock_guard<std::mutex> lk(g_manifestMtx);
        bool mFirst = true;
        for (const auto &m : g_manifest)
        {
            if (!mFirst) j += ',';
            j += "\n    {\"platform\":\"";
            j += jsonEsc(m.platform);
            j += "\",\"version\":\"";
            j += jsonEsc(m.version);
            j += "\",\"filename\":\"";
            j += jsonEsc(m.filename);
            j += "\",\"sha256\":\"";
            j += jsonEsc(m.sha256hex);
            j += "\"}";
            mFirst = false;
        }
    }
    j += "\n  ]";

    j += "\n}\n";
    return j;
}

// ---------------------------------------------------------------------------
// Embedded login/registration HTML/CSS/JS (WebAuthn passkey flow)
// ---------------------------------------------------------------------------

static const char kLoginHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NTM Dashboard &#8212; Sign In</title>
<style>
*{box-sizing:border-box}
body{font-family:monospace;background:#0e0e14;color:#ccc;margin:0;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:16px}
.card{background:#111118;border:1px solid #252535;border-radius:6px;padding:28px 32px;
  width:100%;max-width:400px}
h1{font-size:1.05em;color:#7af;margin:0 0 20px}
.section{color:#7af;font-size:0.78em;text-transform:uppercase;letter-spacing:.06em;margin:20px 0 8px}
.lbl{font-size:0.8em;color:#888;margin-bottom:4px}
input[type=password],input[type=text]{background:#0e0e14;border:1px solid #3a3a5a;color:#ccc;
  padding:7px 10px;font-family:monospace;font-size:0.85em;border-radius:3px;width:100%;
  margin-bottom:10px;outline:none}
input:focus{border-color:#7af}
button{font-family:monospace;font-size:0.82em;padding:7px 16px;border-radius:3px;
  border:1px solid #3a3a5a;cursor:pointer;outline:none;width:100%}
.btn-p{background:#1a1a2e;color:#7af;border-color:#4a4a7a}
.btn-p:hover{background:#222240;color:#adf}
.btn-s{background:#111118;color:#888;border-color:#252535;margin-top:8px}
.btn-s:hover{color:#ccc}
button:disabled{opacity:0.5;cursor:default}
.divider{border:none;border-top:1px solid #252535;margin:20px 0}
#msg{font-size:0.8em;margin-top:12px;min-height:1.2em}
.err{color:#c44}.ok{color:#4c4}
</style>
</head>
<body>
<div class="card">
  <h1>Network Traffic Monitor</h1>
  <div class="section">Sign In</div>
  <button class="btn-p" id="bl" onclick="doLogin()">Sign in with a passkey</button>
  <hr class="divider">
  <div class="section">Register a New Device</div>
  <div class="lbl">Admin password</div>
  <input type="password" id="pwd" placeholder="Admin password" autocomplete="off">
  <div class="lbl">Device label (optional)</div>
  <input type="text" id="lbl" placeholder="e.g. iPhone 15" maxlength="64">
  <button class="btn-s" id="br" onclick="doRegister()">Register this device</button>
  <div id="msg"></div>
</div>
<script>
function msg(t,e){const m=document.getElementById('msg');m.textContent=t;m.className=e?'err':t?'ok':'';}
function b2b(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';
  const b=atob(s),a=new Uint8Array(b.length);
  for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;
}
function bb2(b){
  const a=new Uint8Array(b),s=Array.from(a,x=>String.fromCharCode(x)).join('');
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function hex(b){return Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');}
async function doLogin(){
  msg('','');const btn=document.getElementById('bl');btn.disabled=true;
  try{
    const r1=await fetch('/auth/login/begin',{cache:'no-store'});
    const d=await r1.json();if(d.error)throw new Error(d.error);
    const ac=(d.credential_ids||[]).map(id=>({type:'public-key',id:b2b(id)}));
    const a=await navigator.credentials.get({publicKey:{
      challenge:b2b(d.challenge),rpId:d.rp_id,allowCredentials:ac,
      userVerification:'preferred',timeout:60000}});
    const r2=await fetch('/auth/login/complete',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_key:d.session_key,
        credential_id:bb2(a.rawId),
        authenticator_data:bb2(a.response.authenticatorData),
        client_data_json:bb2(a.response.clientDataJSON),
        signature:bb2(a.response.signature)})});
    const d2=await r2.json();if(!r2.ok||d2.error)throw new Error(d2.error||'Auth failed');
    msg('Signed in — redirecting…',false);
    setTimeout(()=>location.href='/',800);
  }catch(e){msg(e.message||String(e),true);btn.disabled=false;}
}
async function doRegister(){
  msg('','');const btn=document.getElementById('br');btn.disabled=true;
  const pw=document.getElementById('pwd').value;
  const lb=document.getElementById('lbl').value||'My Device';
  if(!pw){msg('Admin password required.',true);btn.disabled=false;return;}
  try{
    const r1=await fetch('/auth/register/begin',{cache:'no-store'});
    const d=await r1.json();if(d.error)throw new Error(d.error);
    const pwb=new TextEncoder().encode(pw);
    const bk=await crypto.subtle.importKey('raw',pwb,'PBKDF2',false,['deriveBits']);
    const db=await crypto.subtle.deriveBits({name:'PBKDF2',salt:b2b(d.pbkdf2_salt),
      iterations:d.pbkdf2_iterations,hash:'SHA-256'},bk,256);
    const hk=await crypto.subtle.importKey('raw',db,{name:'HMAC',hash:'SHA-256'},false,['sign']);
    const proof=hex(await crypto.subtle.sign('HMAC',hk,b2b(d.admin_nonce)));
    const cred=await navigator.credentials.create({publicKey:{
      challenge:b2b(d.challenge),
      rp:{id:d.rp_id,name:d.rp_name},
      user:{id:b2b(d.user_id),name:'admin',displayName:'Admin'},
      pubKeyCredParams:[{type:'public-key',alg:-7}],
      authenticatorSelection:{authenticatorAttachment:'platform',
        residentKey:'preferred',requireResidentKey:false,userVerification:'preferred'},
      timeout:60000,attestation:'none'}});
    const r2=await fetch('/auth/register/complete',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_key:d.session_key,admin_proof:proof,
        attestation_object:bb2(cred.response.attestationObject),
        client_data_json:bb2(cred.response.clientDataJSON),label:lb})});
    const d2=await r2.json();if(!r2.ok||d2.error)throw new Error(d2.error||'Registration failed');
    msg('Device registered — you can now sign in.',false);
  }catch(e){msg(e.message||String(e),true);}
  btn.disabled=false;
}
</script>
</body>
</html>
)HTML";

// ---------------------------------------------------------------------------
// Embedded dashboard HTML/CSS/JS
// ---------------------------------------------------------------------------

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
.tabs{display:flex;gap:0;margin:8px 0 0}
.tab{padding:4px 14px;cursor:pointer;border:1px solid #252535;border-bottom:none;border-radius:3px 3px 0 0;font-size:0.82em;color:#666;background:#111118;font-family:monospace;outline:none}
.tab.active{color:#7af;background:#0e0e14;border-color:#3a3a5a}
.tabpanel{border-top:1px solid #252535;padding-top:4px}
.hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px}
.hdr-links{display:flex;gap:14px;align-items:baseline}
.admin-lnk{font-size:0.78em;color:#7af;text-decoration:none;opacity:0.7}
.admin-lnk:hover{opacity:1}
.logout-btn{font-size:0.78em;color:#888;background:none;border:none;padding:0;font-family:monospace;cursor:pointer;opacity:0.7}
.logout-btn:hover{color:#c66;opacity:1}
.flt-row{display:flex;gap:4px;margin:4px 0 6px}
.flt{background:#111118;color:#666;border:1px solid #252535;padding:2px 10px;font-family:monospace;font-size:0.78em;border-radius:3px;cursor:pointer;outline:none}
.flt.active{color:#7af;border-color:#4a4a7a;background:#0e0e14}
.ovhd-bar{font-size:0.75em;color:#c84;margin-bottom:4px;padding:3px 6px;background:#1a1008;border-left:2px solid #c84}
</style>
</head>
<body>
<div class="hdr">
  <h1>Network Traffic Monitor</h1>
  <div class="hdr-links">
    <a href="/admin" class="admin-lnk">Admin</a>
    <button class="logout-btn" onclick="doLogout()">Sign out</button>
  </div>
</div>
<div id="status"><span id="dot" class="dot ok"></span><span id="smsg">Loading&#8230;</span></div>
<div class="meta">
  Server: <span id="sver">&#8212;</span> &nbsp;|&nbsp;
  Window start: <span id="win">&#8212;</span> &nbsp;|&nbsp;
  Updated: <span id="gen">&#8212;</span> &nbsp;|&nbsp;
  Auto-refresh: 30 s
</div>

<div class="section">Interfaces</div>
<table><thead><tr><th>Client</th><th>Interface</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody id="iface_body"></tbody></table>
<div class="note" id="iface_note"></div>

<div class="section">Entity Flows</div>
<div class="tabs">
  <button class="tab active" id="tab-summary" onclick="showTab('summary')">Entity Summary</button>
  <button class="tab" id="tab-lan" onclick="showTab('lan')">LAN Detail</button>
</div>
<div id="sec-summary" class="tabpanel">
  <div class="flt-row">
    <button class="flt" id="flt-all" onclick="setFilter('all')">All</button>
    <button class="flt active" id="flt-internet" onclick="setFilter('internet')">Internet</button>
    <button class="flt" id="flt-local" onclick="setFilter('local')">Local</button>
    <button class="flt" id="flt-overhead" onclick="setFilter('overhead')">Overhead</button>
  </div>
  <div id="local-bar" class="ovhd-bar" style="display:none;border-color:#7af;color:#7af;background:#080d1a"></div>
  <div id="ovhd-bar" class="ovhd-bar" style="display:none"></div>
  <table><thead><tr><th>Client</th><th>Interface</th><th>Src Entity</th><th>Dst Entity</th><th>Packets</th><th>Bytes</th></tr></thead>
  <tbody id="entity_body"></tbody></table>
  <div class="note" id="entity_note"></div>
</div>
<div id="sec-lan" class="tabpanel" style="display:none">
  <table><thead><tr><th>LAN IP</th><th>Reported by</th><th>Out Packets</th><th>Out Bytes</th><th>In Packets</th><th>In Bytes</th></tr></thead>
  <tbody id="lan_body"></tbody></table>
  <div class="note" id="lan_note"></div>
</div>


<script>
async function doLogout(){
  try{await fetch('/auth/logout',{method:'POST'});}catch(_){}
  window.location.href='/login';
}
const POLL_MS=30000;
let allEntities=[];
let internetEntities=[];
let localEntities=[];
let overheadEntities=[];
let filterMode='internet';
function fmtB(b){
  if(b<1024)return b+'B';
  if(b<1048576)return(b/1024).toFixed(1)+'K';
  if(b<1073741824)return(b/1048576).toFixed(1)+'M';
  return(b/1073741824).toFixed(2)+'G';
}
function fmtT(ep){return ep?new Date(ep*1000).toLocaleString():'—';}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function row(cells){return'<tr>'+cells.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>';}
function showTab(name){
  ['summary','lan'].forEach(function(t){
    document.getElementById('tab-'+t).className='tab'+(t===name?' active':'');
    document.getElementById('sec-'+t).style.display=t===name?'':'none';
  });
}
function setFilter(mode){
  filterMode=mode;
  ['all','internet','local','overhead'].forEach(function(m){
    document.getElementById('flt-'+m).className='flt'+(m===mode?' active':'');
  });
  renderEntities();
}
function renderEntities(){
  let ents;
  if(filterMode==='overhead') ents=overheadEntities;
  else if(filterMode==='local') ents=localEntities;
  else if(filterMode==='internet') ents=internetEntities;
  else if(filterMode==='all'){
    ents=[...allEntities,...overheadEntities].sort(function(a,b){return b.bytes-a.bytes;});
  }else ents=internetEntities;
  document.getElementById('entity_body').innerHTML=
    ents.length?ents.map(x=>row([x.client||'(ip-auth)',x.iface,
      x.src_entity,x.dst_entity,x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
    :'<tr><td colspan="6" style="color:#555">No data</td></tr>';
}
async function refresh(){
  try{
    const r=await fetch('/api/summary',{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    const sv=d.server_version||'?';
    document.getElementById('sver').textContent='v'+sv;
    document.getElementById('win').textContent=fmtT(d.window_start);
    document.getElementById('gen').textContent=fmtT(d.generated_at);
    const ifaces=d.interfaces||[];
    document.getElementById('iface_body').innerHTML=
      ifaces.length?ifaces.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="4" style="color:#555">No data yet</td></tr>';
    allEntities=d.entities||[];
    internetEntities=d.entities_internet||allEntities;
    localEntities=d.entities_local||[];
    overheadEntities=d.overhead_entities||[];
    renderEntities();
    document.getElementById('entity_note').textContent=
      (d.truncated||d.truncated_overhead||d.truncated_internet||d.truncated_local)?'Some results truncated to server limit.':'';
    const ls=d.local_summary;
    const localBar=document.getElementById('local-bar');
    if(ls&&ls.bytes>0){
      localBar.textContent='Local traffic: '+fmtB(ls.bytes)+' ('+ls.pct_of_total_bytes+'% of all traffic)';
      localBar.style.display='';
    }else{localBar.style.display='none';}
    const os=d.overhead_summary;
    const bar=document.getElementById('ovhd-bar');
    if(os&&os.bytes>0){
      bar.textContent='Monitoring overhead: '+fmtB(os.bytes)+' ('+os.pct_of_total_bytes+'% of all traffic)';
      bar.style.display='';
    }else{bar.style.display='none';}
    const lans=d.entities_lan||[];
    document.getElementById('lan_body').innerHTML=
      lans.length?lans.map(x=>row([x.ip,x.reported_by||'—',
        x.out_packets.toLocaleString(),fmtB(x.out_bytes),
        x.in_packets.toLocaleString(),fmtB(x.in_bytes)])).join('')
      :'<tr><td colspan="6" style="color:#555">No unidentified LAN devices detected</td></tr>';
    document.getElementById('lan_note').textContent=
      d.truncated_lan?'Results truncated to server limit.':'';
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

// ---------------------------------------------------------------------------
// Embedded admin HTML/CSS/JS
// ---------------------------------------------------------------------------

static const char kAdminHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NTM Admin</title>
<style>
*{box-sizing:border-box}
body{font-family:monospace;background:#0e0e14;color:#ccc;margin:0;padding:16px}
h1{font-size:1.05em;margin:0 0 4px;color:#7af}
.back{font-size:0.78em;color:#7af;text-decoration:none;opacity:0.7}
.back:hover{opacity:1}
.hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:14px}
.section{color:#7af;font-size:0.82em;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 6px}
.sub{font-size:0.78em;color:#666;margin-bottom:10px}
table{border-collapse:collapse;width:100%;font-size:0.82em;margin-bottom:4px}
th{background:#161622;color:#888;text-align:left;padding:5px 10px;border-bottom:1px solid #252535;white-space:nowrap}
td{padding:4px 10px;border-bottom:1px solid #1a1a28;white-space:nowrap}
tr.selectable{cursor:pointer}
tr.selectable:hover td{background:#171726}
tr.selected td{background:#1a1a2e;color:#cce}
tr.selected td:first-child::before{content:'▶ ';color:#7af}
.panel{border:1px solid #3a3a5a;border-radius:4px;padding:16px;margin-top:14px;background:#0d0d1a}
.warn{color:#c84;font-size:0.88em;margin-bottom:10px}
.panel-title{font-size:0.9em;color:#cce;margin-bottom:10px}
.btn-row{display:flex;gap:10px;margin-top:14px}
button{font-family:monospace;font-size:0.82em;padding:5px 14px;border-radius:3px;border:1px solid #3a3a5a;cursor:pointer;outline:none}
.btn-cancel{background:#111118;color:#888}
.btn-cancel:hover{color:#ccc}
.btn-purge{background:#3a1010;color:#c84;border-color:#5a2020}
.btn-purge:hover{background:#4a1818;color:#f96}
.btn-purge:disabled{opacity:0.5;cursor:default}
.err-msg{font-size:0.8em;color:#c44}
.ok-panel{border:1px solid #2a5a2a;border-radius:4px;padding:16px;margin-top:14px;background:#0a150a}
.ok-title{color:#4c4;font-size:0.9em;margin-bottom:6px}
.ok-sub{font-size:0.8em;color:#666;margin-bottom:12px}
.btn-back{background:#111118;color:#7af;border-color:#3a3a5a}
.btn-back:hover{color:#adf}
#msg{font-size:0.78em;color:#666;margin-top:6px}
.demo-dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle;margin-right:7px}
.btn-demo-on{background:#0d2010;color:#4c4;border-color:#1a4020}
.btn-demo-on:hover{background:#152a18;color:#6e6}
.btn-demo-on:disabled{opacity:0.4;cursor:default}
</style>
</head>
<body>

<div id="main-content">
<div class="hdr">
  <h1>Network Traffic Monitor &mdash; Admin</h1>
  <a href="/" class="back" id="back-link">&#8592; Back to Dashboard</a>
</div>

<!-- ── Active Monitors ────────────────────────────────────────────────── -->
<div class="section">Active Monitors</div>
<div class="sub">Wire agents sending traffic data, and dashboard clients currently polling the server.</div>

<div class="section" style="font-size:0.72em;margin:8px 0 4px;color:#555">Wire Agents</div>
<table>
  <thead><tr><th>Client</th><th>Version</th><th>Wire Proto</th><th>pcap recv</th><th>Kernel drop</th><th>Buf drop</th><th>Last report</th><th>Update</th></tr></thead>
  <tbody id="health_body"><tr><td colspan="8" style="color:#555">Loading&#8230;</td></tr></tbody>
</table>
<div id="proto-reject-banner" style="display:none;background:#3a2000;color:#fa0;border-radius:5px;padding:8px 14px;margin:6px 0;font-size:0.88em"></div>
<div id="proto-rejected-section" style="display:none">
  <div class="section" style="font-size:0.72em;margin:8px 0 4px;color:#555">Protocol-Rejected Connections</div>
  <table><thead><tr><th>Peer IP</th><th>Attempted Auth Version</th><th>Time</th></tr></thead>
  <tbody id="proto_rejected_body"></tbody></table>
</div>

<div class="section" style="font-size:0.72em;margin:14px 0 4px;color:#555">Dashboard Clients</div>
<table>
  <thead><tr><th>IP Address</th><th>Last Seen</th><th>Status</th></tr></thead>
  <tbody id="monitors_body"><tr><td colspan="3" style="color:#555">Loading&#8230;</td></tr></tbody>
</table>

<!-- ── Manage Clients ─────────────────────────────────────────────────── -->
<div class="section" style="margin-top:22px">Manage Clients</div>
<div class="sub" id="list_sub">Select a client to purge all its historical traffic data.</div>
<table>
  <thead><tr><th>Client</th><th>Interfaces</th><th>Packets</th><th>Bytes</th></tr></thead>
  <tbody id="client_body"><tr><td colspan="4" style="color:#555">Loading&#8230;</td></tr></tbody>
</table>

<div id="confirm_panel" style="display:none" class="panel">
  <div class="warn">&#9888;&nbsp; This permanently deletes all historical traffic records for this client.
  Data will accumulate fresh from the next connection.</div>
  <div class="panel-title">Purge all data for: <span id="selected_name" style="color:#7af"></span></div>
  <div class="btn-row">
    <button class="btn-cancel" onclick="cancelSelect()">Cancel</button>
    <button class="btn-purge" id="purge_btn" onclick="doPurge()">Purge Client Data</button>
  </div>
  <div class="err-msg" id="purge_error" style="margin-top:8px"></div>
</div>

<div id="result_panel" style="display:none" class="ok-panel">
  <div class="ok-title">&#10003;&nbsp; <span id="result_client"></span> &mdash; data purged successfully.</div>
  <div class="ok-sub">Data will accumulate fresh from the next client connection.</div>
  <div class="btn-row">
    <button class="btn-back" onclick="resetView()">Back to client list</button>
  </div>
</div>
<div id="msg"></div>

<!-- ── Software Updates ──────────────────────────────────────────────── -->
<div class="section" style="margin-top:22px">Software Updates</div>
<div class="sub">Place binaries in the server update directory. Naming convention: <code style="background:#111118;padding:1px 4px;border-radius:2px">ntm-client-linux-amd64-1.9.0</code> / <code style="background:#111118;padding:1px 4px;border-radius:2px">ntm-client-windows-amd64-1.9.0.exe</code>. Auto-update clients check once per day; use Force Update per agent to push immediately regardless of version.</div>
<div style="display:flex;align-items:center;margin-bottom:10px">
  <button id="scan_btn" onclick="doScanManifest()" style="font-family:monospace;font-size:0.82em;padding:5px 14px;border-radius:3px;border:1px solid #3a5a8a;background:#0d1828;color:#7af;cursor:pointer">&#8635;&nbsp;Scan &amp; Refresh Manifest</button>
  <span id="scan_msg" style="font-size:0.78em;color:#666;margin-left:14px"></span>
</div>
<table>
  <thead><tr><th>Platform</th><th>Latest Version</th><th>Filename</th><th>SHA-256 (first 16 chars)</th></tr></thead>
  <tbody id="manifest_body"><tr><td colspan="4" style="color:#555">No binaries detected &mdash; click Scan or use update_dir in server config</td></tr></tbody>
</table>

<!-- ── Demo Server ────────────────────────────────────────────────────── -->
<div class="section" style="margin-top:22px">Demo Server <span style="font-size:0.75em;color:#555;text-transform:none;letter-spacing:0">&mdash; App Store review</span></div>
<div class="sub">Serves mock data via a time-limited token. Enable only when an App Store reviewer needs access. Resets to <strong>Disabled</strong> on server restart.</div>
<div class="panel">
  <div style="display:flex;align-items:center;margin-bottom:14px">
    <span id="demo_dot" class="demo-dot" style="background:#555"></span>
    <span id="demo_label" style="font-size:0.88em;color:#999">Loading&hellip;</span>
  </div>
  <div class="btn-row">
    <button id="demo_on_btn" class="btn-demo-on" onclick="setDemo(true)" disabled>Enable Demo Server</button>
    <button id="demo_off_btn" class="btn-purge" onclick="setDemo(false)" disabled>Disable Demo Server</button>
  </div>
  <div class="err-msg" id="demo_err" style="margin-top:8px"></div>
</div>
</div><!-- /main-content -->

<script>
function fmtB(b){
  if(b<1024)return b+'B';
  if(b<1048576)return(b/1024).toFixed(1)+'K';
  if(b<1073741824)return(b/1048576).toFixed(1)+'M';
  return(b/1073741824).toFixed(2)+'G';
}
function fmtT(ep){return ep?new Date(ep*1000).toLocaleString():'—';}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

let selectedClient=null;

function handleAdminExpiry(status){
  if(status===403){window.location.href='/admin';return true;}
  return false;
}

async function loadClients(){
  try{
    const r=await fetch('/api/summary',{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    // Build manifest lookup: platform → latest entry
    const manifest=d.update_manifest||[];
    const latestByPlatform={};
    for(const m of manifest){
      const cur=latestByPlatform[m.platform];
      if(!cur||semverGt(m.version,cur.version))latestByPlatform[m.platform]=m;
    }
    // Render manifest table
    const mBody=document.getElementById('manifest_body');
    if(manifest.length){
      mBody.innerHTML=manifest.map(m=>`<tr><td>${esc(m.platform)}</td><td>${esc(m.version)}</td><td>${esc(m.filename)}</td><td style="font-size:0.78em;color:#888">${esc(m.sha256.substring(0,16))}…</td></tr>`).join('');
    }else{
      mBody.innerHTML='<tr><td colspan="4" style="color:#555">No binaries detected — click Scan or use update_dir in server config</td></tr>';
    }
    // Wire agents health
    const srvWireProto=d.server_wire_proto_version||0;
    const health=d.client_health||[];
    document.getElementById('health_body').innerHTML=
      health.length?health.map(function(x){
        const pd=parseFloat(x.pcap_drop_pct);
        const bd=parseFloat(x.buf_drop_pct);
        const pdC=pd>1?'#c44':pd>0.1?'#c84':'#4c4';
        const bdC=bd>1?'#c44':bd>0.1?'#c84':'#4c4';
        const st=x.stale?' <span style="color:#888">(stale)</span>':'';
        let wpBadge;
        if(x.wire_proto_version==null){wpBadge='<span style="color:#555">?</span>';}
        else if(x.wire_proto_ok){wpBadge='<span style="color:#4c4">&#10003; v'+x.wire_proto_version+'</span>';}
        else{wpBadge='<span style="color:#c44">&#10007; v'+x.wire_proto_version+' (server v'+srvWireProto+')</span>';}
        // Update availability
        let updCell='<span style="color:#555">—</span>';
        let rowBg='';
        if(x.platform&&x.client_id){
          const latest=latestByPlatform[x.platform];
          if(latest){
            if(semverGt(latest.version,x.version||'0.0.0')){
              updCell='<span style="color:#c84">&#9650; v'+esc(latest.version)+'</span> '
                +'<button onclick="doForceUpdate(\''+esc(x.client_id)+'\')" '
                +'style="font-size:0.75em;padding:2px 8px;background:#3a1a00;color:#c84;'
                +'border:1px solid #5a3000;border-radius:2px;cursor:pointer;font-family:monospace">Force</button>';
              rowBg='background:#1a1400';
            }else{
              updCell='<span style="color:#4c4">&#10003; current</span>';
            }
          }
        }
        return'<tr style="'+rowBg+'"><td>'+esc(x.client)+st+'</td><td style="color:#aaa">'+esc(x.version)+'</td><td>'+
          wpBadge+'</td><td>'+x.pcap_recv.toLocaleString()+'</td><td style="color:'+pdC+'">'+
          x.pcap_drop.toLocaleString()+' ('+x.pcap_drop_pct+'%)</td><td style="color:'+bdC+'">'+
          x.buf_drop.toLocaleString()+' ('+x.buf_drop_pct+'%)</td><td>'+fmtT(x.reported_at)+'</td>'
          +'<td>'+updCell+'</td></tr>';
      }).join(''):'<tr><td colspan="8" style="color:#555">No wire agents connected</td></tr>';
    // Proto-rejected
    const rejected=d.proto_rejected_clients||[];
    const rejSec=document.getElementById('proto-rejected-section');
    const rejBanner=document.getElementById('proto-reject-banner');
    if(rejected.length){
      rejSec.style.display='';
      document.getElementById('proto_rejected_body').innerHTML=rejected.map(function(r){
        return'<tr><td>'+esc(r.peer_ip)+'</td><td style="color:#c44">'+r.attempted_auth_version+
          '</td><td>'+fmtT(r.at)+'</td></tr>';
      }).join('');
      rejBanner.textContent='Warning: '+rejected.length+' connection(s) rejected — auth-protocol mismatch.';
      rejBanner.style.display='';
    }else{rejSec.style.display='none';rejBanner.style.display='none';}
    // Client list for purge
    const clients={};
    for(const x of (d.interfaces||[])){
      const name=x.client||'(ip-auth)';
      if(!clients[name])clients[name]={ifaces:[],packets:0,bytes:0};
      clients[name].ifaces.push(x.iface);
      clients[name].packets+=x.packets;
      clients[name].bytes+=x.bytes;
    }
    const tbody=document.getElementById('client_body');
    const names=Object.keys(clients);
    if(!names.length){
      tbody.innerHTML='<tr><td colspan="4" style="color:#555">No clients have recorded data yet</td></tr>';
    }else{
      tbody.innerHTML=names.map(name=>{
        const c=clients[name];
        return`<tr class="selectable" data-client="${esc(name)}">
          <td>${esc(name)}</td><td>${esc(c.ifaces.join(', '))}</td>
          <td>${c.packets.toLocaleString()}</td><td>${fmtB(c.bytes)}</td></tr>`;
      }).join('');
      tbody.querySelectorAll('tr').forEach(tr=>{
        tr.addEventListener('click',()=>selectClient(tr.dataset.client));
      });
    }
    // Demo status
    updateDemoStatus(!!d.demo_server_enabled);
    document.getElementById('msg').textContent='';
  }catch(e){
    document.getElementById('client_body').innerHTML=
      '<tr><td colspan="4" style="color:#a33">Error: '+esc(e.message)+'</td></tr>';
  }
}

async function loadMonitors(){
  try{
    const r=await fetch('/api/admin/monitors',{cache:'no-store'});
    if(handleAdminExpiry(r.status))return;
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    const now=Math.floor(Date.now()/1000);
    const dc=d.dashboard_clients||[];
    dc.sort((a,b)=>b.last_seen-a.last_seen);
    document.getElementById('monitors_body').innerHTML=
      dc.length?dc.map(x=>{
        const age=now-x.last_seen;
        const active=age<=300;
        const dot=`<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${active?'#4c4':'#555'};margin-right:6px"></span>`;
        return'<tr><td>'+esc(x.ip)+'</td><td>'+fmtT(x.last_seen)+'</td><td>'+dot+(active?'Active':'Recently seen')+'</td></tr>';
      }).join('')
      :'<tr><td colspan="3" style="color:#555">No dashboard clients seen yet</td></tr>';
  }catch(e){
    document.getElementById('monitors_body').innerHTML=
      '<tr><td colspan="3" style="color:#a33">Error: '+esc(e.message)+'</td></tr>';
  }
}

function selectClient(name){
  selectedClient=name;
  document.querySelectorAll('#client_body tr').forEach(tr=>{
    tr.className=tr.dataset.client===name?'selectable selected':'selectable';
  });
  document.getElementById('selected_name').textContent=name;
  document.getElementById('confirm_panel').style.display='';
  document.getElementById('result_panel').style.display='none';
  document.getElementById('purge_error').textContent='';
  document.getElementById('purge_btn').disabled=false;
  document.getElementById('purge_btn').textContent='Purge Client Data';
}

function cancelSelect(){
  selectedClient=null;
  document.querySelectorAll('#client_body tr').forEach(tr=>tr.className='selectable');
  document.getElementById('confirm_panel').style.display='none';
}

async function doPurge(){
  const btn=document.getElementById('purge_btn');
  btn.disabled=true;btn.textContent='Purging…';
  document.getElementById('purge_error').textContent='';
  try{
    const r=await fetch('/api/admin/purge',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({client:selectedClient})
    });
    if(handleAdminExpiry(r.status)){btn.disabled=false;btn.textContent='Purge Client Data';return;}
    const d=await r.json();
    if(r.ok&&d.ok){
      document.getElementById('confirm_panel').style.display='none';
      document.getElementById('result_client').textContent=selectedClient;
      document.getElementById('result_panel').style.display='';
      loadClients();
    }else{
      document.getElementById('purge_error').textContent=
        r.status===404?'✗ Client not found':'✗ '+(d.error||'Unknown error');
      btn.disabled=false;btn.textContent='Purge Client Data';
    }
  }catch(e){
    document.getElementById('purge_error').textContent='✗ Request failed: '+e.message;
    btn.disabled=false;btn.textContent='Purge Client Data';
  }
}

function resetView(){
  selectedClient=null;
  document.getElementById('result_panel').style.display='none';
  document.getElementById('confirm_panel').style.display='none';
  document.querySelectorAll('#client_body tr').forEach(tr=>tr.className='selectable');
  loadClients();
}

function updateDemoStatus(on){
  document.getElementById('demo_dot').style.background=on?'#4c4':'#c44';
  document.getElementById('demo_label').textContent=on?'Enabled':'Disabled';
  document.getElementById('demo_on_btn').disabled=on;
  document.getElementById('demo_off_btn').disabled=!on;
}

async function setDemo(enabled){
  document.getElementById('demo_err').textContent='';
  try{
    const r=await fetch('/api/admin/demo',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({enabled:enabled})
    });
    if(handleAdminExpiry(r.status))return;
    const d=await r.json();
    if(r.ok&&d.ok){updateDemoStatus(d.demo_enabled);}
    else{document.getElementById('demo_err').textContent='✗ '+(d.error||'Unknown error');}
  }catch(e){
    document.getElementById('demo_err').textContent='✗ Request failed: '+esc(e.message);
  }
}

function semverGt(a,b){
  const pa=(a||'0').split('.').map(Number),pb=(b||'0').split('.').map(Number);
  for(let i=0;i<3;i++){const ai=pa[i]||0,bi=pb[i]||0;if(ai>bi)return true;if(ai<bi)return false;}
  return false;
}

async function doForceUpdate(clientId){
  document.getElementById('msg').textContent='Requesting force update…';
  try{
    const r=await fetch('/api/admin/update/force',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:clientId})
    });
    if(handleAdminExpiry(r.status))return;
    const d=await r.json();
    document.getElementById('msg').textContent=
      (r.ok&&d.ok)?'Force update flagged. Agent will update on next daily check.':'✗ '+(d.error||'Error');
  }catch(e){document.getElementById('msg').textContent='✗ Request failed: '+esc(e.message);}
}

async function doScanManifest(){
  document.getElementById('scan_msg').textContent='Scanning…';
  document.getElementById('scan_btn').disabled=true;
  try{
    const r=await fetch('/api/admin/update/scan',{
      method:'POST',headers:{'Content-Type':'application/json'}
    });
    if(handleAdminExpiry(r.status)){document.getElementById('scan_btn').disabled=false;return;}
    const d=await r.json();
    if(r.ok&&d.ok){
      document.getElementById('scan_msg').textContent='Found '+d.count+' binary(ies).';
      loadClients();
    }else{
      document.getElementById('scan_msg').textContent='✗ '+(d.error||'Scan failed');
    }
  }catch(e){
    document.getElementById('scan_msg').textContent='✗ Request failed: '+esc(e.message);
  }
  document.getElementById('scan_btn').disabled=false;
}

async function loadAll(){
  await Promise.all([loadClients(),loadMonitors()]);
}

loadAll();
</script>
</body>
</html>
)HTML";

// ---------------------------------------------------------------------------
// Admin authentication page — shown when ntm_admin cookie is absent/expired.
// ---------------------------------------------------------------------------
static const char kAdminAuthHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NTM Admin &mdash; Authentication</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d1a;color:#ccc;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#0d0d1a;border:1px solid #3a3a5a;border-radius:6px;padding:32px 36px;min-width:320px;max-width:400px;width:100%}
h2{color:#7af;font-size:0.95em;margin-bottom:20px;font-weight:normal;letter-spacing:0.03em}
label{font-size:0.78em;color:#888;display:block;margin-bottom:6px}
input[type=password]{background:#111118;border:1px solid #3a3a5a;color:#ccc;padding:7px 10px;font-family:monospace;font-size:0.9em;border-radius:3px;width:100%;outline:none;margin-bottom:12px}
input[type=password]:focus{border-color:#7af}
button{background:#101828;color:#7af;border:1px solid #3a5a8a;border-radius:3px;padding:8px 0;width:100%;font-family:monospace;font-size:0.9em;cursor:pointer}
button:hover{background:#182040}
button:disabled{opacity:0.5;cursor:default}
#err{color:#c44;font-size:0.8em;min-height:1.1em;margin-bottom:10px}
.back{display:block;margin-top:16px;font-size:0.78em;color:#555;text-align:center;text-decoration:none}
.back:hover{color:#888}
</style>
</head>
<body>
<div class="card">
  <h2>&#128274;&nbsp; Admin Authentication</h2>
  <label for="pwd">Admin password</label>
  <input type="password" id="pwd" autocomplete="current-password" placeholder="Enter admin password">
  <div id="err"></div>
  <button id="btn" onclick="doAuth()">Enter Admin</button>
  <a href="/" class="back">&#8592; Back to Dashboard</a>
</div>
<script>
async function doAuth(){
  const btn=document.getElementById('btn');
  const pwd=document.getElementById('pwd').value;
  document.getElementById('err').textContent='';
  if(!pwd)return;
  btn.disabled=true;btn.textContent='Verifying…';
  try{
    const r=await fetch('/api/admin/auth',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    const d=await r.json();
    if(r.ok&&d.ok){window.location.href='/admin';}
    else{
      document.getElementById('err').textContent='✗ '+(d.error||'Incorrect password');
      document.getElementById('pwd').value='';
      document.getElementById('pwd').focus();
    }
  }catch(e){
    document.getElementById('err').textContent='✗ Request failed: '+e.message;
  }
  btn.disabled=false;btn.textContent='Enter Admin';
}
document.getElementById('pwd').addEventListener('keydown',e=>{if(e.key==='Enter')doAuth();});
document.getElementById('pwd').focus();
</script>
</body>
</html>
)HTML";

// ---------------------------------------------------------------------------
// Web server thread
// ---------------------------------------------------------------------------

void webServerThread(httplib::SSLServer &svr,
                     TrafficStats &stats,
                     const WebConfig &config)
{
    WebRateLimiter rateLimiter(config.rate_limit_rpm);
    // Separate, much stricter limiter for the admin purge endpoint.
    WebRateLimiter adminRateLimiter(5);

    // Scan update directory on startup so the manifest is populated immediately.
    if (!config.update_dir.empty())
        scanUpdateDir(config.update_dir);

    // Pre-routing: authentication, rate limit, security headers.
    svr.set_pre_routing_handler(
        [&](const httplib::Request &req, httplib::Response &res) -> httplib::Server::HandlerResponse
        {
            const std::string ip    = effectiveClientIP(req, config);
            const std::string &path = req.path;

            if (!rateLimiter.tryAcquire(ip))
            {
                res.status = 429;
                res.set_header("Retry-After", "60");
                res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            // WebAuthn passkey session required for all paths except auth endpoints.
            bool isAuthPath = (path == "/login") ||
                              (path.size() >= 6 && path.substr(0, 6) == "/auth/") ||
                              (path == "/.well-known/apple-app-site-association") ||
                              (path == "/api/demo/begin") ||
                              // Update endpoints authenticate via pubkey query param.
                              (path == "/api/update/check") ||
                              (path == "/api/update/download");
            if (!isAuthPath)
            {
                const std::string token = sessionFromRequest(req);

                // Demo token fast-path — checked before WebAuthn session validation.
                if (checkDemoToken(token))
                {
                    // Block admin paths for demo tokens.
                    if (path.size() >= 11 && path.substr(0, 11) == "/api/admin/")
                    {
                        res.status = 403;
                        res.set_content("{\"error\":\"admin access not available in demo mode\"}\n",
                                        "application/json");
                        return httplib::Server::HandlerResponse::Handled;
                    }
                    return httplib::Server::HandlerResponse::Unhandled;
                }

                if (token.empty() || !config.webauthn->isValidSession(token))
                {
                    bool isApiReq = (path.size() >= 4 && path.substr(0, 4) == "/api") ||
                                    req.method != "GET";
                    if (isApiReq)
                    {
                        res.status = 401;
                        res.set_content("{\"error\":\"authentication required\"}\n",
                                        "application/json");
                    }
                    else
                    {
                        res.status = 302;
                        res.set_header("Location", "/login");
                    }
                    return httplib::Server::HandlerResponse::Handled;
                }
                // Authenticated dashboard client — record IP for overhead classification.
                if (config.dashboard_ips) config.dashboard_ips->add(ip);

                // Admin API paths additionally require the short-lived ntm_admin cookie
                // issued by POST /api/admin/auth (password re-verification).
                // /api/admin/auth itself is exempt — it is the issuance endpoint.
                const bool isAdminApiPath = path.size() >= 11 &&
                                            path.substr(0, 11) == "/api/admin/";
                if (isAdminApiPath && path != "/api/admin/auth")
                {
                    if (!checkAdminProofToken(cookieFromRequest(req, "ntm_admin")))
                    {
                        res.status = 403;
                        res.set_content("{\"error\":\"admin authentication required\"}\n",
                                        "application/json");
                        return httplib::Server::HandlerResponse::Handled;
                    }
                }
            }

            // Security headers on every response.
            res.set_header("X-Content-Type-Options", "nosniff");
            res.set_header("Content-Security-Policy",
                           "default-src 'self'; "
                           "script-src 'self' 'unsafe-inline'; "
                           "style-src 'self' 'unsafe-inline'");
            return httplib::Server::HandlerResponse::Unhandled;
        });

    // GET / — embedded monitoring dashboard HTML
    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(kDashboardHtml, "text/html; charset=utf-8");
    });

    // GET /login — passkey login/registration page
    svr.Get("/login", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(kLoginHtml, "text/html; charset=utf-8");
    });

    // GET /admin — serve full dashboard or password entry page based on ntm_admin cookie.
    // WebAuthn session is already verified by pre-routing; the ntm_admin cookie is the
    // second factor proving the visitor knows the admin password.
    const bool adminAvailable = (config.webauthn && config.webauthn->enabled());
    if (adminAvailable)
    {
        svr.Get("/admin", [](const httplib::Request &req, httplib::Response &res) {
            if (checkAdminProofToken(cookieFromRequest(req, "ntm_admin")))
                res.set_content(kAdminHtml, "text/html; charset=utf-8");
            else
                res.set_content(kAdminAuthHtml, "text/html; charset=utf-8");
        });
    }

    // GET /api/summary — JSON snapshot of aggregated traffic
    svr.Get("/api/summary",
        [&stats, &config](const httplib::Request &req, httplib::Response &res) {
            res.set_header("Cache-Control", "no-store");
            // Demo session — return mock data, never expose real traffic stats.
            if (checkDemoToken(sessionFromRequest(req)))
            {
                res.set_content(buildDemoSummaryJson(), "application/json");
                return;
            }
            res.set_content(buildSummaryJson(stats, config.max_entity_lines,
                                             config.client_nicknames, config.registry,
                                             config.server_ips, config.dashboard_ips),
                            "application/json");
        });

    // POST /api/admin/auth — verify admin password and issue ntm_admin proof cookie.
    // Requires a valid WebAuthn session (pre-routing) but NOT the ntm_admin cookie.
    // Rate-limited to prevent brute-force.
    if (adminAvailable)
    {
        svr.Post("/api/admin/auth",
            [&config, &adminRateLimiter](const httplib::Request &req, httplib::Response &res)
            {
                if (!adminRateLimiter.tryAcquire(effectiveClientIP(req, config)))
                {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                    return;
                }
                const std::string password = jsonGetString(req.body, "password");
                if (password.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"password required\"}\n", "application/json");
                    return;
                }
                if (!config.webauthn->verifyAdminPassword(password))
                {
                    serverLog(LogLevel::Warn,
                              "ntm-server: admin auth REJECTED from %s",
                              effectiveClientIP(req, config).c_str());
                    res.status = 401;
                    res.set_content("{\"error\":\"incorrect password\"}\n", "application/json");
                    return;
                }
                const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                const std::string token = generateAdminProofToken();
                {
                    std::lock_guard<std::mutex> lk(g_adminProofMtx);
                    // Lazy GC: prune expired tokens on each new login.
                    for (auto it = g_adminProofTokens.begin(); it != g_adminProofTokens.end(); )
                        it = (now >= it->second) ? g_adminProofTokens.erase(it) : std::next(it);
                    g_adminProofTokens.emplace(token, now + kAdminProofTokenSec);
                }
                serverLog(LogLevel::Info,
                          "ntm-server: admin auth OK from %s",
                          effectiveClientIP(req, config).c_str());
                res.set_header("Set-Cookie",
                               "ntm_admin=" + token +
                               "; HttpOnly; Secure; SameSite=Strict"
                               "; Max-Age=" + std::to_string(kAdminProofTokenSec) +
                               "; Path=/");
                res.set_content("{\"ok\":true}\n", "application/json");
            });
    }

    // GET /api/admin/monitors — list active wire agents and recent dashboard clients.
    if (adminAvailable)
    {
        svr.Get("/api/admin/monitors",
            [&config](const httplib::Request &, httplib::Response &res)
            {
                res.set_header("Cache-Control", "no-store");
                const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                std::string j = "{\"wire_agents\":[],\"dashboard_clients\":[";
                // Dashboard clients from MonitoringIpSet (timestamped).
                if (config.dashboard_ips)
                {
                    bool first = true;
                    for (const auto &e : config.dashboard_ips->snapshot())
                    {
                        if (!first) j += ',';
                        j += "{\"ip\":\"";
                        j += jsonEsc(e.ip);
                        j += "\",\"last_seen\":";
                        j += std::to_string(e.lastSeen);
                        j += ",\"active\":";
                        j += (now - e.lastSeen <= 300) ? "true" : "false";
                        j += '}';
                        first = false;
                    }
                }
                j += "]}\n";
                res.set_content(j, "application/json");
            });
    }

    // POST /api/admin/purge — erase one client's data
    if (adminAvailable)
    {
        svr.Post("/api/admin/purge",
            [&stats, &config, &adminRateLimiter](const httplib::Request &req,
                                                  httplib::Response &res)
            {
                const std::string ip = effectiveClientIP(req, config);

                // Strict per-IP rate limit for the admin endpoint.
                if (!adminRateLimiter.tryAcquire(ip))
                {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                    return;
                }

                // Parse JSON body.
                const std::string &body = req.body;
                std::string clientName = jsonGetString(body, "client");

                if (clientName.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"bad request: client field required\"}\n",
                                    "application/json");
                    return;
                }

                // Session already verified by pre-routing handler.

                // Resolve display name → hex client ID.
                // Try nickname reverse lookup first, then accept a raw 64-char hex ID directly.
                std::string hexId;
                for (const auto &kv : config.client_nicknames)
                {
                    if (kv.second == clientName) { hexId = kv.first; break; }
                }
                if (hexId.empty() && clientName.size() == 64)
                {
                    bool allHex = true;
                    for (char c : clientName)
                        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) { allHex=false; break; }
                    if (allHex) hexId = clientName;
                }
                // Also accept display name that equals the hex ID (no nickname configured).
                if (hexId.empty())
                {
                    for (const auto &kv : config.client_nicknames)
                        if (kv.first == clientName) { hexId = kv.first; break; }
                }
                if (hexId.empty())
                {
                    serverLog(LogLevel::Warn,
                              "ntm-server: admin purge from %s: client '%s' not found",
                              ip.c_str(), clientName.c_str());
                    res.status = 404;
                    res.set_content("{\"error\":\"client not found\"}\n", "application/json");
                    return;
                }

                bool hadData = stats.purgeClient(hexId);
                serverLog(LogLevel::Warn,
                          "ntm-server: admin purge from %s: client '%s' (id=%s) purged (%s)",
                          ip.c_str(), clientName.c_str(), hexId.c_str(),
                          hadData ? "data erased" : "no data was present");

                std::string resp = "{\"ok\":true,\"client_id\":\"";
                resp += jsonEsc(hexId);
                resp += "\",\"message\":\"client data purged\"}\n";
                res.set_content(resp, "application/json");
            });
    }

    // POST /api/admin/client/register — enroll a new Ed25519 wire-protocol client key
    if (adminAvailable && config.clients_store)
    {
        svr.Post("/api/admin/client/register",
            [&config, &adminRateLimiter](const httplib::Request &req, httplib::Response &res)
            {
                const std::string ip = effectiveClientIP(req, config);
                if (!adminRateLimiter.tryAcquire(ip))
                {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                    return;
                }

                const std::string &body = req.body;
                std::string pubkeyHex = jsonGetString(body, "pubkey");
                std::string nickname  = jsonGetString(body, "nickname");

                if (pubkeyHex.size() != 64)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"pubkey must be 64 hex characters\"}\n",
                                    "application/json");
                    return;
                }
                for (char c : pubkeyHex)
                {
                    if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')))
                    {
                        res.status = 400;
                        res.set_content("{\"error\":\"pubkey must be lowercase hex\"}\n",
                                        "application/json");
                        return;
                    }
                }
                if (nickname.size() > 64)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"nickname too long (max 64 characters)\"}\n",
                                    "application/json");
                    return;
                }
                for (char c : nickname)
                {
                    if (c == '|' || static_cast<unsigned char>(c) < 0x20u)
                    {
                        res.status = 400;
                        res.set_content("{\"error\":\"nickname contains invalid characters\"}\n",
                                        "application/json");
                        return;
                    }
                }

                // Decode hex to 32-byte raw key
                std::string rawKey;
                rawKey.reserve(32);
                for (std::size_t i = 0; i < 64; i += 2)
                {
                    auto h = [](char c) -> int {
                        return (c>='a') ? c-'a'+10 : (c>='A') ? c-'A'+10 : c-'0';
                    };
                    rawKey.push_back(static_cast<char>((h(pubkeyHex[i]) << 4) | h(pubkeyHex[i+1])));
                }

                auto &store = *config.clients_store;
                {
                    std::unique_lock<std::shared_mutex> lk(store.mu);

                    if (store.keys.count(rawKey))
                    {
                        res.status = 409;
                        res.set_content("{\"error\":\"pubkey already registered\"}\n",
                                        "application/json");
                        return;
                    }

                    // Append to file before updating memory — fail fast if unwritable.
                    if (!store.filePath.empty())
                    {
                        std::ofstream f(store.filePath, std::ios::app);
                        if (!f)
                        {
                            serverLog(LogLevel::Err,
                                      "ntm-server: client/register: cannot write to allowed-keys file '%s': %s",
                                      store.filePath.c_str(), strerror(errno));
                            res.status = 500;
                            res.set_content("{\"error\":\"server error: cannot write keys file\"}\n",
                                            "application/json");
                            return;
                        }
                        f << pubkeyHex;
                        if (!nickname.empty())
                            f << " " << nickname;
                        f << "\n";
                        if (!f)
                        {
                            serverLog(LogLevel::Err,
                                      "ntm-server: client/register: write error on allowed-keys file '%s'",
                                      store.filePath.c_str());
                            res.status = 500;
                            res.set_content("{\"error\":\"server error: cannot write keys file\"}\n",
                                            "application/json");
                            return;
                        }
                    }

                    store.keys.insert(rawKey);
                    if (!nickname.empty())
                        store.nicknames[pubkeyHex] = nickname;
                }

                serverLog(LogLevel::Warn,
                          "ntm-server: client registered from %s: pubkey=%.16s... nickname='%s'",
                          ip.c_str(), pubkeyHex.c_str(), nickname.c_str());

                std::string resp = "{\"ok\":true,\"client_id\":\"";
                resp += jsonEsc(pubkeyHex);
                resp += "\"}\n";
                res.set_content(resp, "application/json");
            });
    }

    // POST /api/admin/demo — enable or disable the demo server at runtime.
    if (adminAvailable)
    {
        svr.Post("/api/admin/demo",
            [&config](const httplib::Request &req, httplib::Response &res)
            {
                // Session already verified by pre-routing handler.

                // Parse {"enabled": true|false}
                const std::string &body = req.body;
                auto pos = body.find("\"enabled\"");
                if (pos == std::string::npos)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"missing enabled field\"}\n", "application/json");
                    return;
                }
                pos = body.find_first_of("tf", pos + 9);
                if (pos == std::string::npos)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"enabled must be true or false\"}\n",
                                    "application/json");
                    return;
                }
                const bool enabled = (body[pos] == 't');
                g_demoEnabled.store(enabled, std::memory_order_relaxed);
                if (enabled)
                {
                    // Reset session so new reviewer gets a full 15-minute window.
                    g_demoSessionStart.store(0, std::memory_order_relaxed);
                }
                serverLog(LogLevel::Warn, "ntm-server: demo server %s by %s",
                          enabled ? "ENABLED" : "DISABLED",
                          effectiveClientIP(req, config).c_str());

                std::string resp = "{\"ok\":true,\"demo_enabled\":";
                resp += enabled ? "true" : "false";
                resp += "}\n";
                res.set_content(resp, "application/json");
            });
    }

    // POST /api/demo/begin — issue a short-lived demo session token (no auth required).
    // Requires demo mode to be enabled by the operator via POST /api/admin/demo.
    svr.Post("/api/demo/begin",
        [&config](const httplib::Request &req, httplib::Response &res)
        {
            if (!g_demoEnabled.load(std::memory_order_relaxed))
            {
                res.status = 503;
                res.set_content("{\"error\":\"demo is disabled\"}\n", "application/json");
                return;
            }
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            const std::string token = generateDemoToken();
            {
                std::lock_guard<std::mutex> lk(g_demoTokensMtx);
                // Lazy GC: prune expired tokens on each issuance.
                for (auto it = g_demoTokens.begin(); it != g_demoTokens.end(); )
                    it = (now >= it->second) ? g_demoTokens.erase(it) : std::next(it);
                g_demoTokens.emplace(token, now + kDemoSessionSec);
            }
            // Reset demo session window so mock data timestamps look fresh.
            g_demoSessionStart.store(0, std::memory_order_relaxed);
            serverLog(LogLevel::Warn, "ntm-server: demo token issued to %s",
                      effectiveClientIP(req, config).c_str());

            std::string resp = "{\"ok\":true,\"token\":\"";
            resp += token;
            resp += "\",\"expires_in\":";
            resp += std::to_string(kDemoSessionSec);
            resp += "}\n";
            res.set_content(resp, "application/json");
        });

    // WebAuthn authentication endpoints.
    if (config.webauthn && config.webauthn->enabled())
    {
        // GET /auth/register/begin — server returns challenge + PBKDF2 params
        svr.Get("/auth/register/begin",
            [&config](const httplib::Request &, httplib::Response &res) {
                res.set_header("Cache-Control", "no-store");
                std::string key;
                res.set_content(config.webauthn->beginRegistration(key), "application/json");
            });

        // POST /auth/register/complete — verify admin proof + WebAuthn credential
        svr.Post("/auth/register/complete",
            [&config, &adminRateLimiter](const httplib::Request &req, httplib::Response &res) {
                if (!adminRateLimiter.tryAcquire(effectiveClientIP(req, config)))
                {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                    return;
                }
                const std::string &b = req.body;
                std::string sessionKey = jsonGetString(b, "session_key");
                std::string proof      = jsonGetString(b, "admin_proof");
                std::string attObj     = jsonGetString(b, "attestation_object");
                std::string cdJson     = jsonGetString(b, "client_data_json");
                std::string label      = jsonGetString(b, "label");
                if (sessionKey.empty() || proof.empty() || attObj.empty() || cdJson.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"missing required fields\"}\n", "application/json");
                    return;
                }
                std::string err = config.webauthn->completeRegistration(
                    sessionKey, proof, attObj, cdJson, label);
                if (!err.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"" + jsonEsc(err) + "\"}\n", "application/json");
                    return;
                }
                res.set_content("{\"ok\":true}\n", "application/json");
            });

        // GET /auth/login/begin — server returns WebAuthn challenge
        svr.Get("/auth/login/begin",
            [&config](const httplib::Request &, httplib::Response &res) {
                res.set_header("Cache-Control", "no-store");
                std::string key;
                res.set_content(config.webauthn->beginAuthentication(key), "application/json");
            });

        // POST /auth/login/complete — verify assertion, set session cookie + return Bearer token
        svr.Post("/auth/login/complete",
            [&config](const httplib::Request &req, httplib::Response &res) {
                const std::string &b = req.body;
                std::string sessionKey = jsonGetString(b, "session_key");
                std::string credId     = jsonGetString(b, "credential_id");
                std::string authData   = jsonGetString(b, "authenticator_data");
                std::string cdJson     = jsonGetString(b, "client_data_json");
                std::string sig        = jsonGetString(b, "signature");
                if (sessionKey.empty() || credId.empty() || authData.empty() ||
                    cdJson.empty()      || sig.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"missing required fields\"}\n", "application/json");
                    return;
                }
                std::string errOut;
                std::string token = config.webauthn->completeAuthentication(
                    sessionKey, credId, authData, cdJson, sig, errOut);
                if (token.empty())
                {
                    res.status = 401;
                    res.set_content("{\"error\":\"" + jsonEsc(errOut) + "\"}\n", "application/json");
                    return;
                }
                // Browser: HttpOnly cookie. iOS app: Bearer token in JSON body.
                res.set_header("Set-Cookie",
                    "ntm_session=" + token +
                    "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400");
                res.set_content("{\"ok\":true,\"token\":\"" + token + "\"}\n", "application/json");
            });

        // POST /auth/logout — invalidate session and clear all auth cookies
        svr.Post("/auth/logout",
            [&config](const httplib::Request &req, httplib::Response &res) {
                std::string token = sessionFromRequest(req);
                if (!token.empty()) config.webauthn->invalidateSession(token);
                // Also invalidate the admin proof token if present.
                std::string adminToken = cookieFromRequest(req, "ntm_admin");
                if (!adminToken.empty())
                {
                    std::lock_guard<std::mutex> lk(g_adminProofMtx);
                    g_adminProofTokens.erase(adminToken);
                }
                const std::string expired = "; HttpOnly; Secure; SameSite=Strict; Path=/; "
                                            "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
                res.set_header("Set-Cookie", "ntm_session=" + expired);
                res.set_header("Set-Cookie", "ntm_admin=" + expired);
                res.set_content("{\"ok\":true}\n", "application/json");
            });

        // GET /.well-known/apple-app-site-association — for iOS passkey domain association
        if (!config.webauthn->aasaJson().empty())
        {
            svr.Get("/.well-known/apple-app-site-association",
                [&config](const httplib::Request &, httplib::Response &res) {
                    res.set_content(config.webauthn->aasaJson(), "application/json");
                });
        }
    }

    // GET /api/update/check — check if a newer binary is available for this client.
    // Query params: pubkey=<64hex>, platform=<platform>, version=<current>
    // Authenticated by pubkey presence in AllowedClientsStore (no session cookie needed).
    if (!config.update_dir.empty() && config.clients_store)
    {
        svr.Get("/api/update/check",
            [&config](const httplib::Request &req, httplib::Response &res)
            {
                res.set_header("Cache-Control", "no-store");
                const std::string pubkeyHex = req.get_param_value("pubkey");
                const std::string platform  = req.get_param_value("platform");
                const std::string version   = req.get_param_value("version");

                // Validate pubkey format.
                if (pubkeyHex.size() != 64)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"pubkey must be 64 hex characters\"}\n",
                                    "application/json");
                    return;
                }
                const std::string rawKey = hexToRaw32(pubkeyHex);
                if (rawKey.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"pubkey must be valid hex\"}\n",
                                    "application/json");
                    return;
                }

                // Verify pubkey is in AllowedClientsStore.
                {
                    std::shared_lock<std::shared_mutex> lk(config.clients_store->mu);
                    if (!config.clients_store->keys.count(rawKey))
                    {
                        res.status = 401;
                        res.set_content("{\"error\":\"unauthorized\"}\n", "application/json");
                        return;
                    }
                }

                // Check force-update flag.
                bool force = false;
                {
                    std::lock_guard<std::mutex> lk(g_forceMtx);
                    auto it = g_forceUpdateClients.find(pubkeyHex);
                    if (it != g_forceUpdateClients.end())
                    {
                        force = true;
                        g_forceUpdateClients.erase(it);
                    }
                }

                // Find latest manifest entry for this platform.
                UpdateManifestEntry best;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lk(g_manifestMtx);
                    for (const auto &m : g_manifest)
                    {
                        if (m.platform == platform)
                        {
                            if (!found || semverCmp(m.version, best.version) > 0)
                            {
                                best  = m;
                                found = true;
                            }
                        }
                    }
                }

                std::string resp = "{\"force\":";
                resp += force ? "true" : "false";

                if (!found || (!force && !version.empty() && semverCmp(best.version, version) <= 0))
                {
                    resp += ",\"update_available\":false}\n";
                    res.set_content(resp, "application/json");
                    return;
                }

                resp += ",\"update_available\":true";
                resp += ",\"version\":\"";  resp += jsonEsc(best.version);  resp += "\"";
                resp += ",\"sha256\":\"";   resp += jsonEsc(best.sha256hex); resp += "\"";
                resp += ",\"filename\":\""; resp += jsonEsc(best.filename);  resp += "\"";
                resp += "}\n";
                res.set_content(resp, "application/json");
            });

        // GET /api/update/download — stream the binary for the requested platform.
        svr.Get("/api/update/download",
            [&config](const httplib::Request &req, httplib::Response &res)
            {
                const std::string pubkeyHex = req.get_param_value("pubkey");
                const std::string platform  = req.get_param_value("platform");

                if (pubkeyHex.size() != 64)
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"pubkey must be 64 hex characters\"}\n",
                                    "application/json");
                    return;
                }
                const std::string rawKey = hexToRaw32(pubkeyHex);
                if (rawKey.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"pubkey must be valid hex\"}\n",
                                    "application/json");
                    return;
                }
                {
                    std::shared_lock<std::shared_mutex> lk(config.clients_store->mu);
                    if (!config.clients_store->keys.count(rawKey))
                    {
                        res.status = 401;
                        res.set_content("{\"error\":\"unauthorized\"}\n", "application/json");
                        return;
                    }
                }

                // Find latest for this platform.
                UpdateManifestEntry best;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lk(g_manifestMtx);
                    for (const auto &m : g_manifest)
                    {
                        if (m.platform == platform)
                        {
                            if (!found || semverCmp(m.version, best.version) > 0)
                            {
                                best  = m;
                                found = true;
                            }
                        }
                    }
                }

                if (!found)
                {
                    res.status = 404;
                    res.set_content("{\"error\":\"no binary for platform\"}\n", "application/json");
                    return;
                }

                namespace fs = std::filesystem;
                fs::path filePath = fs::path(config.update_dir) / best.filename;
                std::ifstream ifs(filePath, std::ios::binary | std::ios::ate);
                if (!ifs)
                {
                    res.status = 404;
                    res.set_content("{\"error\":\"binary not accessible\"}\n", "application/json");
                    return;
                }
                auto fileSize = ifs.tellg();
                ifs.seekg(0);
                std::string body(static_cast<std::size_t>(fileSize), '\0');
                ifs.read(body.data(), fileSize);
                res.set_header("Content-Disposition",
                               "attachment; filename=\"" + best.filename + "\"");
                res.set_content(body, "application/octet-stream");
            });

        // POST /api/admin/update/scan — (re-)scan update_dir, rebuild manifest.
        if (adminAvailable)
        {
            svr.Post("/api/admin/update/scan",
                [&config](const httplib::Request &, httplib::Response &res)
                {
                    std::size_t count = scanUpdateDir(config.update_dir);
                    serverLog(LogLevel::Info,
                              "ntm-server: update manifest refreshed: %zu binary(ies)", count);
                    std::string resp = "{\"ok\":true,\"count\":";
                    resp += std::to_string(count);
                    resp += "}\n";
                    res.set_content(resp, "application/json");
                });
        }

        // POST /api/admin/update/force — flag a client for forced update on next check.
        if (adminAvailable)
        {
            svr.Post("/api/admin/update/force",
                [&config](const httplib::Request &req, httplib::Response &res)
                {
                    const std::string pubkeyHex = jsonGetString(req.body, "pubkey");
                    if (pubkeyHex.size() != 64)
                    {
                        res.status = 400;
                        res.set_content("{\"error\":\"pubkey must be 64 hex characters\"}\n",
                                        "application/json");
                        return;
                    }
                    // Verify the client exists in AllowedClientsStore.
                    const std::string rawKey = hexToRaw32(pubkeyHex);
                    if (rawKey.empty() || !config.clients_store)
                    {
                        res.status = 400;
                        res.set_content("{\"error\":\"invalid pubkey\"}\n", "application/json");
                        return;
                    }
                    {
                        std::shared_lock<std::shared_mutex> lk(config.clients_store->mu);
                        if (!config.clients_store->keys.count(rawKey))
                        {
                            res.status = 404;
                            res.set_content("{\"error\":\"client not in allowed list\"}\n",
                                            "application/json");
                            return;
                        }
                    }
                    {
                        std::lock_guard<std::mutex> lk(g_forceMtx);
                        g_forceUpdateClients.insert(pubkeyHex);
                    }
                    serverLog(LogLevel::Warn,
                              "ntm-server: force update flagged for client %.16s…",
                              pubkeyHex.c_str());
                    res.set_content("{\"ok\":true}\n", "application/json");
                });
        }
    }

    // All other paths → 404
    svr.set_error_handler([](const httplib::Request &, httplib::Response &res) {
        if (res.status == 404)
            res.set_content("{\"error\":\"not found\"}\n", "application/json");
    });

    svr.listen(config.bind, static_cast<int>(config.port));
}

// ---------------------------------------------------------------------------
// Demo server thread (App Store review — port kDemoPort)
// ---------------------------------------------------------------------------

void demoServerThread(httplib::SSLServer &svr)
{
    svr.set_pre_routing_handler(
        [](const httplib::Request &req, httplib::Response &res) -> httplib::Server::HandlerResponse
        {
            // Reject browsers and common non-iOS HTTP clients by User-Agent.
            // All major browsers send "Mozilla"; block curl, python, and Postman too.
            const std::string &ua = req.get_header_value("User-Agent");
            auto uaHas = [&](const char *s) { return ua.find(s) != std::string::npos; };
            if (uaHas("Mozilla") || uaHas("curl/") || uaHas("python") || uaHas("PostmanRuntime"))
            {
                res.status = 403;
                res.set_content("{\"error\":\"demo port is for iOS app only\"}\n",
                                "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            if (!g_demoEnabled.load(std::memory_order_relaxed))
            {
                res.status = 503;
                res.set_content("{\"error\":\"demo server is disabled\"}\n", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            res.set_header("X-Content-Type-Options", "nosniff");
            return httplib::Server::HandlerResponse::Unhandled;
        });

    svr.Get("/api/summary",
        [](const httplib::Request &, httplib::Response &res) {
            res.set_header("Cache-Control", "no-store");
            res.set_content(buildDemoSummaryJson(), "application/json");
        });

    svr.set_error_handler([](const httplib::Request &, httplib::Response &res) {
        if (res.status == 404)
            res.set_content("{\"error\":\"not found\"}\n", "application/json");
    });

    svr.listen("0.0.0.0", static_cast<int>(kDemoPort));
}

} // namespace ntm
