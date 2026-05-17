// ntm-server: headless aggregation daemon / foreground process
// Receives PacketMeta lines from ntm-client over TCP and aggregates
// by interface, IP pair, and country pair.

#include "proto_client_server.hpp"
#include "ntm_types.hpp"
#include "web_dashboard.hpp"
// httplib.h comes transitively via web_dashboard.hpp

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

    // IPRangeResolver / IPDataUpdater configuration.
    std::string ip_db_path{"/var/lib/ntm-server/ip2asn-combined.tsv.gz"};
    std::string ip_db_url{"https://iptoasn.com/data/ip2asn-combined.tsv.gz"};
    unsigned ip_db_update_interval_days{7};
    bool ip_db_auto_update{true};
    std::size_t max_flow_entries_per_key{100000};
    std::size_t max_entity_flow_entries_per_key{100000};
    // UB-1: hard cap on distinct iface names per client.
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
    // NEW-N6: report (but don't fatally fail on) chdir/dup2 errors.
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

    if (!sslCtx)
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
    if (allowedKeys.empty())
    {
        return;
    }
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

    // Idle-recv-block fix: bound the per-recv blocking time so the loop can re-check
    // idle_timeout_seconds and g_running periodically.
    {
        unsigned pollSecs = config.idle_timeout_seconds;
        if (pollSecs == 0 || pollSecs > 30) pollSecs = 30;
        // NEW-N5: explicitly fail this connection if we cannot install the timeout.
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
    // exceeded its iface cap. Logged only on power-of-two crossings.
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
                    // long-lived connections the benefit of background DB updates.
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
                    // UB-1: log on power-of-two crossings so a misbehaving client
                    // surfaces but cannot spam syslog.
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
    // NEW-N3: wrap each iteration so a transient bad_alloc doesn't kill the entire daemon.
    while (g_running.load())
    {
        try
        {
        // UE-2 (extra): chunk the inter-iteration sleep so g_running is checked frequently.
        for (int i = 0; i < 20; ++i)
        {
            if (!g_running.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        if (!g_running.load())
            break;

        // H2: in daemon mode suppress the detailed periodic printout.
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

        // NEW-M2: route detailed verbose stats through one sink.
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
    // UE-2: poll stdin with a small timeout so the watcher checks g_running periodically.
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
                continue;
            if (pr < 0)
            {
                if (errno == EINTR) continue;
                serverLog(LogLevel::Warn, "ntm-server: stdin poll failed: %s",
                          std::strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }
            if (pfd.revents & (POLLHUP | POLLNVAL))
                break;
            if (!(pfd.revents & POLLIN))
                continue;
            char c = 0;
            ssize_t n = ::read(STDIN_FILENO, &c, 1);
            if (n <= 0)
                break;
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
              const ServerConfig &config)
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
        serverLog(LogLevel::Warn, "ntm-server: TLS enabled, plain TCP refused (session max %u hours)",
                  static_cast<unsigned>(kMaxSessionSeconds / 3600));
    }
    else
    {
        serverLog(LogLevel::Err, "ntm-server: TLS is mandatory; set cert and key in config or via --cert/--key");
        return 1;
    }

    // NEW-H1: fail-closed authentication.
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
        serverLog(LogLevel::Err,
                  "ntm-server: client authentication is mandatory; "
                  "set allowed_keys in config or via --allowed-keys");
        if (sslCtx) SSL_CTX_free(sslCtx);
        return 1;
    }

    TrafficStats stats(config.aggregation_window_days,
                       config.max_flow_entries_per_key,
                       config.max_entity_flow_entries_per_key,
                       config.max_ifaces_per_client);

    // IP-to-country/ASN resolver + background auto-updater.
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

    // Start HTTPS web dashboard if web_port > 0.
    // Build WebConfig from ServerConfig so the web side stays decoupled.
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
                    // Populate WebConfig: the web thread only gets the fields it actually uses.
                    WebConfig webCfg;
                    webCfg.port             = config.web_port;
                    webCfg.bind             = config.web_bind;
                    webCfg.token            = config.web_token;
                    webCfg.rate_limit_rpm   = config.web_rate_limit_rpm;
                    webCfg.max_entity_lines = config.max_entity_lines_in_summary;

                    webThread = std::thread(webServerThread,
                                            std::ref(*webSvr),
                                            std::ref(stats),
                                            webCfg);
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

    // H1: self-pruning worker tracking.
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
            // UE-1: triage accept() errors.
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
        // UE-3: if inet_ntop fails, use a synthetic key so the per-IP cap still works.
        std::string clientIpStr;
        if (ntop)
        {
            clientIpStr.assign(addrBuf);
        }
        else
        {
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

        // NEW-N2: spawn the worker exception-safely.
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
                          doneFlag);
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

    // Stop the IP data updater BEFORE freeing SSL_CTX.
    ipDataUpdater.stop();

    // Free SSL_CTX after all workers have released their SSL objects.
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
                "Usage: ntm-server [--daemon] [--verbose] [--port N]\n"
                "                  [--allowed-keys FILE] [--cert PEM] [--key PEM]\n"
                "                  [--web-port N] [--web-bind IP] [--web-token TOKEN]\n"
                "                  [--config FILE]\n"
                "  TLS (--cert/--key) and client authentication (--allowed-keys) are mandatory.\n"
                "  Options can be set in config file (key=value); command-line overrides config.\n";
            return 0;
        }
    }

    // M7: load config exactly once and fail loudly if --config was given but the
    // file could not be opened.
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
    if (!verbose) verbose = config.verbose;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        if (arg == "--daemon")
            daemonMode = true;
        else if (arg == "--verbose")
            verbose = true;
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
                          certPath, keyPath, config);
}
