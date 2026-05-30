// updater.cpp — background auto-update for ntm-client (Linux + Windows).
// Self-locates the binary, polls /api/update/check daily, downloads, verifies
// SHA-256, and atomically replaces the binary on disk.

#include "updater.hpp"
#include "client_core.hpp"
#include "client_version.hpp"
#include "client_signing.hpp"
#include "client_http_util.hpp"

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
#  include <shlobj.h>    // SHGetFolderPathW / CSIDL_COMMON_APPDATA (staging dir)
#  ifdef NTM_REQUIRE_AUTHENTICODE
#    include <wintrust.h>  // WinVerifyTrust
#    include <softpub.h>   // WINTRUST_ACTION_GENERIC_VERIFY_V2
#  endif
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
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>

namespace ntm
{

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static std::atomic<bool> g_updaterRunning{false};
static std::atomic<bool> g_updateInProgress{false};
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

#ifdef _WIN32
// HARMONIZE-LINUX: Windows separates the download staging dir from the install dir so
// the service identity never needs write access to Program Files at download time.
// Linux puts the pending file directly in the binary directory (install dir == staging dir).
// Falls back to exeDir() if SHGetFolderPathW fails (e.g. portable/non-standard setup).
static std::string updateStagingDir()
{
    wchar_t buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, buf)))
    {
        fs::path staging = fs::path(buf) / "ntm-client" / "staging";
        std::error_code ec;
        fs::create_directories(staging, ec);
        if (!ec)
            return staging.string();
    }
    return exeDir();
}
#endif

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
    std::error_code ec;
#ifdef _WIN32
    std::string old            = dir + "/ntm-client.exe.old";
    std::string pendingLocal   = dir + "/ntm-client-pending.exe";
    std::string pendingStaging = updateStagingDir() + "/ntm-client-pending.exe";
    fs::remove(pendingLocal,   ec);
    fs::remove(pendingStaging, ec);
#else
    std::string old = dir + "/ntm-client.pending";
#endif
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
    // L-2: guard against CR/LF injection via a hostile config-file server value.
    if (!ntm::http_util::hasValidHostname(host))
    {
        std::cerr << "ntm-client: updater: invalid server hostname (contains CR/LF)\n";
        return {0, {}};
    }
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
    // L-2: guard against CR/LF injection via a hostile config-file server value.
    if (!ntm::http_util::hasValidHostname(host))
    {
        std::cerr << "ntm-client: updater: invalid server hostname (contains CR/LF)\n";
        return 0;
    }
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

    // Hard ceiling: abort if more bytes arrive than a sane update could ever be.
    // Protects against a compromised server returning an unbounded body when size==0.
    constexpr std::int64_t kAbsoluteMaxBytes = 256LL * 1024 * 1024;
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
        if (written > kAbsoluteMaxBytes)
        {
            std::fclose(f);
            std::cerr << "ntm-client: updater: download exceeded 256 MiB absolute cap; aborting\n";
            return 0;
        }
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
    const std::string pending    = dir + "/ntm-client.pending";
    const std::string pendingSig = dir + "/ntm-client.pending.sig";
    const std::string target     = dir + "/ntm-client";
    const std::string targetSig  = dir + "/ntm-client.sig";

    // Make executable.
    std::error_code ec;
    fs::permissions(pending,
                    fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                    fs::perm_options::add, ec);
    if (ec) return false;

    // Atomic rename: replaces target path; running process keeps old inode.
    if (std::rename(pending.c_str(), target.c_str()) != 0) return false;

    // Move sig file (best-effort; if missing, startup verification will fail but
    // the binary update succeeded)
    if (fs::exists(pendingSig, ec) && !ec)
        std::rename(pendingSig.c_str(), targetSig.c_str());

    return true;
}

#ifdef _WIN32
// HARMONIZE-LINUX: Windows apply path diverges from Linux here (staging dir, MoveFileExW,
// smoke test, optional Authenticode). During the next cross-platform audit, consider
// whether the smoke-test and rollback logic should be lifted into a shared helper.

// Atomically swap the downloaded binary into place.
// pendingPath / pendingSigPath come from the staging dir (may be cross-volume).
// MOVEFILE_COPY_ALLOWED handles the cross-volume case transparently.
static bool applyUpdateWindows(const std::string &installDir,
                               const std::string &pendingPath,
                               const std::string &pendingSigPath)
{
    const std::string target    = installDir + "/ntm-client.exe";
    const std::string targetSig = installDir + "/ntm-client.exe.sig";
    const std::string old_      = installDir + "/ntm-client.exe.old";
    const std::string oldSig_   = installDir + "/ntm-client.exe.sig.old";

    const std::wstring wtarget(target.begin(), target.end());
    const std::wstring wold(old_.begin(), old_.end());
    const std::wstring wpending(pendingPath.begin(), pendingPath.end());

    // Rename running exe to .old (allowed while running on NTFS Vista+).
    if (!MoveFileExW(wtarget.c_str(), wold.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return false;

    // Place new binary at the original path; MOVEFILE_COPY_ALLOWED handles cross-volume
    // (staging dir under %ProgramData% may differ from Program Files install dir).
    if (!MoveFileExW(wpending.c_str(), wtarget.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED |
                     MOVEFILE_WRITE_THROUGH))
    {
        MoveFileExW(wold.c_str(), wtarget.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        return false;
    }

    // Move sig file (best-effort)
    std::error_code ec;
    if (fs::exists(pendingSigPath, ec) && !ec)
    {
        const std::wstring wsigPending(pendingSigPath.begin(), pendingSigPath.end());
        const std::wstring wsigTarget(targetSig.begin(), targetSig.end());
        const std::wstring wsigOld(oldSig_.begin(), oldSig_.end());
        MoveFileExW(wsigTarget.c_str(), wsigOld.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        MoveFileExW(wsigPending.c_str(), wsigTarget.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH);
    }
    return true;
}

// Smoke-test the new binary by running it with --version.
// Returns true if the process exits 0 within 10 seconds.
static bool smokeTestNewBinary(const std::string &exePath)
{
    std::wstring wexe(exePath.begin(), exePath.end());
    std::wstring cmdline = L"\"" + wexe + L"\" --version";
    std::vector<wchar_t> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(wexe.c_str(), mutableCmd.data(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return false;
    DWORD wr = WaitForSingleObject(pi.hProcess, 10'000);
    DWORD exitCode = 1;
    if (wr == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &exitCode);
    else TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return wr == WAIT_OBJECT_0 && exitCode == 0;
}

#ifdef NTM_REQUIRE_AUTHENTICODE
// Verify Authenticode signature of a binary using WinVerifyTrust.
// Only compiled when -DNTM_REQUIRE_AUTHENTICODE is passed to cmake.
// TODO: extract signer subject and compare against NTM_AUTHENTICODE_SUBJECT
//       (CryptQueryObject + CertGetNameStringW); deferred to a follow-up PR.
static bool verifyAuthenticode(const std::wstring &filePath)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct      = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct          = sizeof(wd);
    wd.dwUIChoice        = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wd.dwUnionChoice     = WTD_CHOICE_FILE;
    wd.pFile             = &fileInfo;
    wd.dwStateAction     = WTD_STATEACTION_VERIFY;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policy, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &wd);
    return status == ERROR_SUCCESS;
}
#endif  // NTM_REQUIRE_AUTHENTICODE
#endif  // _WIN32

// ---------------------------------------------------------------------------
// Main update loop
// ---------------------------------------------------------------------------

static std::int64_t epochNow()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void doOneCheckCycle(const ClientConfig &config,
                     UpdateTrigger trigger,
                     const UpdateCallbacks &cb)
{
    // Serialise: only one update cycle at a time across periodic + push paths.
    bool expected = false;
    if (!g_updateInProgress.compare_exchange_strong(expected, true))
    {
        if (cb.onNoop) cb.onNoop("in_progress");
        return;
    }
    struct InProgressGuard {
        ~InProgressGuard() { g_updateInProgress.store(false); }
    } ipGuard;

    const std::string dir = exeDir();
    if (dir.empty())
    {
        std::cerr << "ntm-client: updater: cannot determine exe directory\n";
        if (cb.onError) cb.onError("network", "cannot-determine-exe-dir");
        return;
    }

    const std::string pubkeyHex = pubkeyHexFromPem(config.identityPath);
    if (pubkeyHex.empty())
    {
        std::cerr << "ntm-client: updater: cannot derive pubkey from identity\n";
        if (cb.onError) cb.onError("network", "cannot-derive-pubkey");
        return;
    }

    // ── Stage: checking ──────────────────────────────────────────────────────
    if (cb.onStage) cb.onStage("checking");

    std::string path = "/api/update/check?platform=";
    path += kClientPlatform;
    path += "&version=";
    path += kClientVersion;
    path += "&pubkey=";
    path += pubkeyHex;

    auto [status, body] = httpsGet(config.server, config.port, path,
                                   config.tlsCaPath, config.tlsServerCertPath,
                                   config.verbose);

    if (trigger == UpdateTrigger::Periodic)
        writeLastCheck(dir, epochNow());

    if (status == 0)
    {
        std::cerr << "ntm-client: updater: check failed (connection error)\n";
        if (cb.onError) cb.onError("network", "connection-error");
        return;
    }
    if (status != 200)
    {
        std::cerr << "ntm-client: updater: check failed (HTTP " << status << ")\n";
        if (cb.onError) cb.onError("network", "http-" + std::to_string(status));
        return;
    }

    const bool available = jsonBool(body, "update_available", false);

    if (!available)
    {
        if (config.verbose)
            std::cerr << "ntm-client: updater: no update available\n";
        if (cb.onNoop) cb.onNoop("no_update_available");
        return;
    }

    const std::string newVer = ntm::http_util::jsonStr(body, "version");
    const std::string sha256 = ntm::http_util::jsonStr(body, "sha256");
    const std::int64_t size  = jsonInt(body, "size", 0);

    if (newVer.empty() || sha256.size() != 64)
    {
        std::cerr << "ntm-client: updater: malformed check response\n";
        if (cb.onError) cb.onError("network", "malformed-check-response");
        return;
    }

    constexpr std::int64_t kMaxUpdateBytes = 64LL * 1024 * 1024;
    if (size > kMaxUpdateBytes)
    {
        std::cerr << "ntm-client: updater: server reported size " << size
                  << " exceeds 64 MiB cap; refusing update\n";
        if (cb.onError) cb.onError("network", "size-cap-exceeded");
        return;
    }

    std::cerr << "ntm-client: updater: update available — " << newVer << "\n";

#ifdef _WIN32
    const std::string stagingDir  = updateStagingDir();
    const std::string pendingPath = stagingDir + "/ntm-client-pending.exe";
#else
    const std::string pendingPath = dir + "/ntm-client.pending";
#endif
    std::error_code ec;
    fs::remove(pendingPath, ec);

    // ── Stage: downloading_binary ────────────────────────────────────────────
    if (cb.onStage) cb.onStage("downloading_binary");

    std::string dlPath = "/api/update/download?platform=";
    dlPath += kClientPlatform;
    dlPath += "&pubkey=";
    dlPath += pubkeyHex;

    int dlStatus = httpsGetToFile(config.server, config.port, dlPath,
                                  config.tlsCaPath, config.tlsServerCertPath,
                                  pendingPath, size, config.verbose);
    if (dlStatus != 200)
    {
        std::cerr << "ntm-client: updater: download failed (HTTP " << dlStatus << ")\n";
        fs::remove(pendingPath, ec);
        if (cb.onError) cb.onError("downloading_binary", "http-" + std::to_string(dlStatus));
        return;
    }

    // ── Stage: verifying_sha256 ──────────────────────────────────────────────
    if (cb.onStage) cb.onStage("verifying_sha256");

    std::string gotHash;
    if (!sha256FileHex(pendingPath, gotHash) || gotHash != sha256)
    {
        std::cerr << "ntm-client: updater: SHA-256 mismatch — discarding download\n";
        fs::remove(pendingPath, ec);
        if (cb.onError) cb.onError("verifying_sha256", "hash-mismatch");
        return;
    }

    std::cerr << "ntm-client: updater: verified " << newVer << " (SHA-256 OK)\n";

    // ── Stage: downloading_signature ─────────────────────────────────────────
    if (cb.onStage) cb.onStage("downloading_signature");

    const std::string pendingSigPath = pendingPath + ".sig";
    { std::error_code ec2; fs::remove(pendingSigPath, ec2); }

    std::string sigDlPath = "/api/update/download_sig?platform=";
    sigDlPath += kClientPlatform;
    sigDlPath += "&pubkey=";
    sigDlPath += pubkeyHex;

    const std::int64_t expectedSigSize = jsonInt(body, "sig_size", 0);
    int sigStatus = httpsGetToFile(config.server, config.port, sigDlPath,
                                   config.tlsCaPath, config.tlsServerCertPath,
                                   pendingSigPath,
                                   expectedSigSize > 0 ? expectedSigSize : 10 * 1024 * 1024,
                                   config.verbose);
    if (sigStatus != 200)
    {
        std::cerr << "ntm-client: updater: signature download failed (HTTP " << sigStatus
                  << ") — discarding update\n";
        fs::remove(pendingPath, ec);
        fs::remove(pendingSigPath, ec);
        if (cb.onError) cb.onError("downloading_signature", "http-" + std::to_string(sigStatus));
        return;
    }

    // ── Stage: verifying_signature ───────────────────────────────────────────
    if (cb.onStage) cb.onStage("verifying_signature");

    {
        std::vector<std::uint8_t> binData, sigData;
        auto readVec = [](const std::string &p, std::vector<std::uint8_t> &out) -> bool {
            FILE *f = std::fopen(p.c_str(), "rb");
            if (!f) return false;
            std::fseek(f, 0, SEEK_END);
            long sz = std::ftell(f); std::rewind(f);
            if (sz <= 0) { std::fclose(f); return false; }
            out.resize(static_cast<std::size_t>(sz));
            bool ok = std::fread(out.data(), 1, out.size(), f) == out.size();
            std::fclose(f);
            return ok;
        };

        if (!readVec(pendingPath, binData) || !readVec(pendingSigPath, sigData))
        {
            std::cerr << "ntm-client: updater: cannot read pending files for verification\n";
            fs::remove(pendingPath, ec);
            fs::remove(pendingSigPath, ec);
            if (cb.onError) cb.onError("verifying_signature", "io-read-error");
            return;
        }

        std::string sigVerErr;
        if (!ntm::signing::verifyClientSignatureBytes(binData, sigData, sigVerErr))
        {
            std::cerr << "ntm-client: updater: ML-DSA-65 verification FAILED — "
                         "discarding update (" << sigVerErr << ")\n";
            fs::remove(pendingPath, ec);
            fs::remove(pendingSigPath, ec);
            if (cb.onError) cb.onError("verifying_signature", sigVerErr);
            return;
        }
        std::cerr << "ntm-client: updater: ML-DSA-65 signature verified OK\n";
    }

    // ── Stage: applying ──────────────────────────────────────────────────────
    if (cb.onStage) cb.onStage("applying");

#ifdef _WIN32
    if (!applyUpdateWindows(dir, pendingPath, pendingSigPath))
    {
        std::cerr << "ntm-client: updater: failed to apply update\n";
        fs::remove(pendingPath, ec);
        if (cb.onError) cb.onError("applying", "apply-failed");
        return;
    }

    const std::string targetExe = dir + "/ntm-client.exe";
    if (!smokeTestNewBinary(targetExe))
    {
        std::cerr << "ntm-client: updater: smoke test failed; rolling back to previous binary\n";
        const std::wstring wTarget(targetExe.begin(), targetExe.end());
        const std::wstring wOldExe((dir + "/ntm-client.exe.old").begin(),
                                   (dir + "/ntm-client.exe.old").end());
        MoveFileExW(wOldExe.c_str(), wTarget.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        fs::remove(pendingPath, ec);
        if (cb.onError) cb.onError("applying", "smoke-test-failed");
        return;
    }

#ifdef NTM_REQUIRE_AUTHENTICODE
    {
        std::wstring wexe(targetExe.begin(), targetExe.end());
        if (!verifyAuthenticode(wexe))
        {
            std::cerr << "ntm-client: updater: Authenticode verification failed; rolling back\n";
            const std::wstring wTarget(targetExe.begin(), targetExe.end());
            const std::wstring wOldExe((dir + "/ntm-client.exe.old").begin(),
                                       (dir + "/ntm-client.exe.old").end());
            MoveFileExW(wOldExe.c_str(), wTarget.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
            fs::remove(pendingPath, ec);
            if (cb.onError) cb.onError("applying", "authenticode-failed");
            return;
        }
    }
#endif  // NTM_REQUIRE_AUTHENTICODE

    // ── Stage: restarting ────────────────────────────────────────────────────
    if (cb.onStage) cb.onStage("restarting");
    if (cb.onDone)  cb.onDone(newVer);
    std::cerr << "ntm-client: updater: update applied; restarting\n";
    ExitProcess(0);
#else
    if (!applyUpdateLinux(dir))
    {
        std::cerr << "ntm-client: updater: failed to apply update\n";
        fs::remove(pendingPath, ec);
        if (cb.onError) cb.onError("applying", "apply-failed");
        return;
    }

    // ── Stage: restarting ────────────────────────────────────────────────────
    if (cb.onStage) cb.onStage("restarting");
    if (cb.onDone)  cb.onDone(newVer);
    std::cerr << "ntm-client: updater: update applied; exec-self to hot-reload\n";
    if (g_argv)
    {
        ::execv(selfExePath().c_str(), g_argv);
        // execv replaces the process; only returns on failure.
    }
    std::cerr << "ntm-client: updater: exec-self failed; binary updated for next restart\n";
    if (cb.onError) cb.onError("exec", "execv-failed");
#endif
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

        doOneCheckCycle(config, UpdateTrigger::Periodic, {});
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
