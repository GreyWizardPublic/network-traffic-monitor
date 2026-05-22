// updater.cpp — background auto-update for ntm-client (Linux + Windows).
// Self-locates the binary, polls /api/update/check daily, downloads, verifies
// SHA-256, and atomically replaces the binary on disk.

#include "updater.hpp"
#include "client_core.hpp"
#include "client_version.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <climits>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>

namespace ntm
{

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static std::atomic<bool> g_updaterRunning{false};
static std::thread       g_updaterThread;
static char            **g_argv{nullptr};

// ---------------------------------------------------------------------------
// Self-location
// ---------------------------------------------------------------------------

static std::string selfExePath()
{
#ifdef _WIN32
    wchar_t buf[32768] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
    if (n == 0) return {};
    return fs::path(buf).string();
#else
    char buf[PATH_MAX] = {};
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return std::string(buf);
#endif
}

static std::string exeDir()
{
    const std::string p = selfExePath();
    if (p.empty()) return {};
    return fs::path(p).parent_path().string();
}

// ---------------------------------------------------------------------------
// State file (last-check timestamp)
// ---------------------------------------------------------------------------

static std::int64_t readLastCheck(const std::string &dir)
{
    const std::string path = dir + "/ntm-client.update-state";
    std::ifstream f(path);
    if (!f) return 0;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("last_check=", 0) == 0)
        {
            try { return std::stoll(line.substr(11)); }
            catch (...) {}
        }
    }
    return 0;
}

static void writeLastCheck(const std::string &dir, std::int64_t t)
{
    const std::string path = dir + "/ntm-client.update-state";
    std::ofstream f(path);
    if (f) f << "last_check=" << t << "\n";
}

// ---------------------------------------------------------------------------
// Startup cleanup (stale .pending or .exe.old from interrupted update)
// ---------------------------------------------------------------------------

static void cleanupStaleFiles(const std::string &dir)
{
#ifdef _WIN32
    std::string old = dir + "/ntm-client.exe.old";
#else
    std::string old = dir + "/ntm-client.pending";
#endif
    std::error_code ec;
    fs::remove(old, ec);
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client (OpenSSL, no httplib dependency)
// ---------------------------------------------------------------------------

#ifdef _WIN32
using SockFdType = SOCKET;
static constexpr SOCKET kBadSock = INVALID_SOCKET;
static void closeSock(SOCKET s) { closesocket(s); }
#else
using SockFdType = int;
static constexpr int kBadSock = -1;
static void closeSock(int s) { ::close(s); }
#endif

struct SockGuard
{
    SockFdType fd;
    explicit SockGuard(SockFdType f) : fd(f) {}
    ~SockGuard() { if (fd != kBadSock) closeSock(fd); }
    SockGuard(const SockGuard &) = delete;
};

struct SslGuard
{
    SSL *ssl;
    explicit SslGuard(SSL *s) : ssl(s) {}
    ~SslGuard() { if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); } }
    SslGuard(const SslGuard &) = delete;
};

static SockFdType connectTcp(const std::string &host, std::uint16_t port)
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return kBadSock;

    SockFdType fd = kBadSock;
    for (auto *ai = res; ai; ai = ai->ai_next)
    {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == kBadSock) continue;
        if (::connect(fd, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) break;
        closeSock(fd);
        fd = kBadSock;
    }
    freeaddrinfo(res);
    return fd;
}

// Builds an SSL connection over fd. Returns nullptr on failure.
static SSL *tlsConnect(SockFdType fd, const std::string &host,
                       const std::string &caPath, const std::string &serverCertPath,
                       bool verbose)
{
    SSL_CTX *ctx = createClientTLSContext(caPath, serverCertPath);
    if (!ctx) return nullptr;
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) return nullptr;

    unsigned char ipBuf[16];
    const bool isIp = (::inet_pton(AF_INET,  host.c_str(), ipBuf) == 1) ||
                      (::inet_pton(AF_INET6, host.c_str(), ipBuf) == 1);
    if (!isIp) SSL_set_tlsext_host_name(ssl, host.c_str());

#ifdef _WIN32
    SSL_set_fd(ssl, static_cast<int>(fd));
#else
    SSL_set_fd(ssl, fd);
#endif
    if (SSL_connect(ssl) != 1)
    {
        if (verbose) ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return nullptr;
    }
    if (!verifyServerIdentityAndPin(ssl, host, serverCertPath, verbose, false))
    {
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

// Read from SSL (or plain fd) until we have at least limit bytes or connection closes.
// Returns all bytes read.
static std::string sslRead(SSL *ssl, SockFdType fd, std::size_t limit = 2 * 1024 * 1024)
{
    std::string out;
    out.reserve(4096);
    char buf[8192];
    while (out.size() < limit)
    {
        int n;
        if (ssl)
            n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
        else
            n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
        if (n <= 0) break;
        out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
}

// Tiny JSON field extractor (string values only, no nesting).
static std::string jsonStr(const std::string &json, const std::string &key)
{
    std::string pattern = "\"" + key + "\":\"";
    auto pos = json.find(pattern);
    if (pos == std::string::npos) return {};
    pos += pattern.size();
    auto end = json.find('"', pos);
    if (end == std::string::npos) return {};
    return json.substr(pos, end - pos);
}

static bool jsonBool(const std::string &json, const std::string &key, bool def = false)
{
    std::string pt = "\"" + key + "\":";
    auto pos = json.find(pt);
    if (pos == std::string::npos) return def;
    pos += pt.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    if (pos + 4 <= json.size() && json.substr(pos, 4) == "true")  return true;
    if (pos + 5 <= json.size() && json.substr(pos, 5) == "false") return false;
    return def;
}

static long long jsonInt(const std::string &json, const std::string &key, long long def = 0)
{
    std::string pt = "\"" + key + "\":";
    auto pos = json.find(pt);
    if (pos == std::string::npos) return def;
    pos += pt.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    char *end = nullptr;
    long long v = std::strtoll(json.c_str() + pos, &end, 10);
    if (end == json.c_str() + pos) return def;
    return v;
}

// Parse HTTP status code from response (0 = failed).
static int parseHttpStatus(const std::string &response)
{
    // "HTTP/1.x NNN "
    if (response.size() < 12) return 0;
    if (response.substr(0, 5) != "HTTP/") return 0;
    auto sp = response.find(' ');
    if (sp == std::string::npos) return 0;
    return static_cast<int>(std::strtol(response.c_str() + sp + 1, nullptr, 10));
}

static std::string parseHttpBody(const std::string &response)
{
    auto sep = response.find("\r\n\r\n");
    if (sep == std::string::npos) return {};
    return response.substr(sep + 4);
}

// Simple HTTPS GET. Returns {status, body} (status 0 = connection failed).
static std::pair<int, std::string> httpsGet(const std::string &host, std::uint16_t port,
                                             const std::string &path,
                                             const std::string &caPath,
                                             const std::string &serverCertPath,
                                             bool verbose)
{
    SockFdType fd = connectTcp(host, port);
    if (fd == kBadSock) return {0, {}};
    SockGuard sg(fd);

    SSL *ssl = tlsConnect(fd, host, caPath, serverCertPath, verbose);
    if (!ssl) return {0, {}};
    SslGuard sslg(ssl);

    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (SSL_write(ssl, req.c_str(), static_cast<int>(req.size())) <= 0) return {0, {}};

    std::string resp = sslRead(ssl, fd);
    return {parseHttpStatus(resp), parseHttpBody(resp)};
}

// HTTPS GET streaming to file. Returns HTTP status (0 = connection failed).
static int httpsGetToFile(const std::string &host, std::uint16_t port,
                          const std::string &path,
                          const std::string &caPath, const std::string &serverCertPath,
                          const std::string &destPath, std::int64_t expectedSize,
                          bool verbose)
{
    SockFdType fd = connectTcp(host, port);
    if (fd == kBadSock) return 0;
    SockGuard sg(fd);

    SSL *ssl = tlsConnect(fd, host, caPath, serverCertPath, verbose);
    if (!ssl) return 0;
    SslGuard sslg(ssl);

    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (SSL_write(ssl, req.c_str(), static_cast<int>(req.size())) <= 0) return 0;

    // Read response headers.
    std::string headers;
    headers.reserve(4096);
    char hbuf[1];
    while (headers.size() < 16384)
    {
        int n = SSL_read(ssl, hbuf, 1);
        if (n <= 0) break;
        headers += hbuf[0];
        if (headers.size() >= 4 &&
            headers.substr(headers.size() - 4) == "\r\n\r\n")
            break;
    }
    int status = parseHttpStatus(headers);
    if (status != 200) return status ? status : 0;

    // Stream body to file.
    FILE *f = std::fopen(destPath.c_str(), "wb");
    if (!f) return 0;

    std::int64_t written = 0;
    char buf[65536];
    while (true)
    {
        int n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
        if (n <= 0) break;
        if (std::fwrite(buf, 1, static_cast<std::size_t>(n), f) != static_cast<std::size_t>(n))
        {
            std::fclose(f);
            return 0;
        }
        written += n;
        if (expectedSize > 0 && written >= expectedSize) break;
    }
    std::fclose(f);
    return 200;
}

// ---------------------------------------------------------------------------
// SHA-256 of a file → 64-char hex string
// ---------------------------------------------------------------------------

static bool sha256FileHex(const std::string &path, std::string &hexOut)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { std::fclose(f); return false; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[65536];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);
    std::fclose(f);

    unsigned char hash[32];
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    static constexpr char kHex[] = "0123456789abcdef";
    hexOut.clear();
    hexOut.reserve(64);
    for (int i = 0; i < 32; ++i)
    {
        hexOut += kHex[hash[i] >> 4];
        hexOut += kHex[hash[i] & 0xfu];
    }
    return true;
}

// ---------------------------------------------------------------------------
// Derive 64-hex Ed25519 pubkey from identity PEM (for /api/update/check auth)
// ---------------------------------------------------------------------------

static std::string pubkeyHexFromPem(const std::string &pemPath)
{
    if (pemPath.empty()) return {};

    FILE *f = std::fopen(pemPath.c_str(), "r");
    if (!f) return {};
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (!pkey) return {};

    std::size_t len = 32;
    unsigned char raw[32] = {};
    int ok = EVP_PKEY_get_raw_public_key(pkey, raw, &len);
    EVP_PKEY_free(pkey);
    if (!ok || len != 32) return {};

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i)
    {
        out += kHex[raw[i] >> 4];
        out += kHex[raw[i] & 0xfu];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Apply update
// ---------------------------------------------------------------------------

static bool applyUpdateLinux(const std::string &dir)
{
    const std::string pending = dir + "/ntm-client.pending";
    const std::string target  = dir + "/ntm-client";

    // Make executable.
    std::error_code ec;
    fs::permissions(pending,
                    fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                    fs::perm_options::add, ec);
    if (ec) return false;

    // Atomic rename: replaces target path; running process keeps old inode.
    if (std::rename(pending.c_str(), target.c_str()) != 0) return false;
    return true;
}

#ifdef _WIN32
static bool applyUpdateWindows(const std::string &dir)
{
    const std::string pending = dir + "/ntm-client-pending.exe";
    const std::string target  = dir + "/ntm-client.exe";
    const std::string old_    = dir + "/ntm-client.exe.old";

    // Rename running exe to .old (allowed while running on NTFS Vista+).
    const std::wstring wtarget(target.begin(), target.end());
    const std::wstring wold(old_.begin(), old_.end());
    const std::wstring wpending(pending.begin(), pending.end());
    const std::wstring wtarget2(target.begin(), target.end());

    if (!MoveFileW(wtarget.c_str(), wold.c_str()))
        return false;

    // Place new binary at the original path.
    if (!MoveFileW(wpending.c_str(), wtarget2.c_str()))
    {
        // Attempt to restore old name on failure.
        MoveFileW(wold.c_str(), wtarget.c_str());
        return false;
    }
    return true;
}
#endif

// ---------------------------------------------------------------------------
// Main update loop
// ---------------------------------------------------------------------------

static std::int64_t epochNow()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static void runUpdater(ClientConfig config)
{
    const std::string dir = exeDir();
    if (dir.empty())
    {
        std::cerr << "ntm-client: updater: cannot determine exe directory; auto-update disabled\n";
        return;
    }

    cleanupStaleFiles(dir);

    const std::string pubkeyHex = pubkeyHexFromPem(config.identityPath);
    if (pubkeyHex.empty())
    {
        std::cerr << "ntm-client: updater: cannot derive pubkey from identity; auto-update disabled\n";
        return;
    }

    // Add ±30-min jitter (0–3600 s random offset subtracted from the 23h interval).
    unsigned char jBuf[2] = {};
    RAND_bytes(jBuf, sizeof(jBuf));
    const std::int64_t jitter = static_cast<std::int64_t>((jBuf[0] << 8 | jBuf[1]) % 3601);
    const std::int64_t checkInterval = 82800 - jitter; // 23h minus up to 1h

    std::cerr << "ntm-client: updater: started (platform=" << kClientPlatform
              << ", check_interval=" << checkInterval << "s)\n";

    while (g_updaterRunning.load())
    {
        // Sleep in 5-second increments so stop() is responsive.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!g_updaterRunning.load()) break;

        const std::string stateDir = dir;
        const std::int64_t lastCheck = readLastCheck(stateDir);
        const std::int64_t now      = epochNow();

        if (now - lastCheck < checkInterval) continue;

        // Build check URL.
        std::string path = "/api/update/check?platform=";
        path += kClientPlatform;
        path += "&version=";
        path += kClientVersion;
        path += "&pubkey=";
        path += pubkeyHex;

        auto [status, body] = httpsGet(config.server, config.update_port, path,
                                       config.tlsCaPath, config.tlsServerCertPath,
                                       config.verbose);

        writeLastCheck(stateDir, epochNow());

        if (status == 0)
        {
            std::cerr << "ntm-client: updater: check failed (connection error)\n";
            continue;
        }
        if (status != 200)
        {
            std::cerr << "ntm-client: updater: check failed (HTTP " << status << ")\n";
            continue;
        }

        const bool available = jsonBool(body, "available", false);
        const bool force      = jsonBool(body, "force",     false);

        if (!available && !force)
        {
            if (config.verbose)
                std::cerr << "ntm-client: updater: no update available\n";
            continue;
        }

        const std::string newVer = jsonStr(body, "version");
        const std::string sha256 = jsonStr(body, "sha256");
        const std::int64_t size  = jsonInt(body, "size", 0);

        if (newVer.empty() || sha256.size() != 64 || size <= 0)
        {
            std::cerr << "ntm-client: updater: malformed check response\n";
            continue;
        }

        std::cerr << "ntm-client: updater: update available — " << newVer
                  << (force ? " (forced)" : "") << "\n";

        // Download path.
#ifdef _WIN32
        const std::string pendingPath = dir + "/ntm-client-pending.exe";
#else
        const std::string pendingPath = dir + "/ntm-client.pending";
#endif
        // Remove stale pending file.
        std::error_code ec;
        fs::remove(pendingPath, ec);

        // Build download URL.
        std::string dlPath = "/api/update/download?platform=";
        dlPath += kClientPlatform;
        dlPath += "&pubkey=";
        dlPath += pubkeyHex;

        int dlStatus = httpsGetToFile(config.server, config.update_port, dlPath,
                                      config.tlsCaPath, config.tlsServerCertPath,
                                      pendingPath, size, config.verbose);
        if (dlStatus != 200)
        {
            std::cerr << "ntm-client: updater: download failed (HTTP " << dlStatus << ")\n";
            fs::remove(pendingPath, ec);
            continue;
        }

        // Verify SHA-256.
        std::string gotHash;
        if (!sha256FileHex(pendingPath, gotHash) || gotHash != sha256)
        {
            std::cerr << "ntm-client: updater: SHA-256 mismatch — discarding download\n";
            fs::remove(pendingPath, ec);
            continue;
        }

        std::cerr << "ntm-client: updater: verified " << newVer << " (SHA-256 OK)\n";

        // Apply.
#ifdef _WIN32
        if (!applyUpdateWindows(dir))
        {
            std::cerr << "ntm-client: updater: failed to apply update\n";
            fs::remove(pendingPath, ec);
            continue;
        }
        std::cerr << "ntm-client: updater: update applied; restarting…\n";
        // Exit so Task Scheduler / SCM restarts with new binary.
        ExitProcess(0);
#else
        if (!applyUpdateLinux(dir))
        {
            std::cerr << "ntm-client: updater: failed to apply update\n";
            fs::remove(pendingPath, ec);
            continue;
        }
        std::cerr << "ntm-client: updater: update applied; exec-self to hot-reload\n";
        // Exec the new binary in-place. argv[0] will show the correct path.
        if (g_argv)
        {
            ::execv(selfExePath().c_str(), g_argv);
            // execv replaces the process; only returns on failure.
        }
        std::cerr << "ntm-client: updater: exec-self failed; binary updated for next restart\n";
#endif
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void startAutoUpdater(const ClientConfig &config, char **argv)
{
    if (!config.auto_update) return;
    g_argv = argv;
    g_updaterRunning.store(true);
    g_updaterThread = std::thread(runUpdater, config);
}

void stopAutoUpdater()
{
    g_updaterRunning.store(false);
    if (g_updaterThread.joinable())
        g_updaterThread.join();
}

} // namespace ntm
