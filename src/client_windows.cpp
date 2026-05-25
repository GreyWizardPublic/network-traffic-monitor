#ifndef _WIN32
#error "client_windows.cpp is only for Windows builds"
#endif

#include "client_platform.hpp"
#include "client_core.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

// Npcap / WinPcap forward type (pcap_if_t defined in pcap.h, included only in client_impl)
#include <pcap/pcap.h>

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace ntm::platform
{

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

bool readExact(SSL *ssl, SockFd fd, void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes) return false;
    auto *p = static_cast<std::uint8_t *>(buf);
    while (n > 0)
    {
        int chunk = static_cast<int>(n < static_cast<std::size_t>(INT_MAX) ? n
                                                                            : static_cast<std::size_t>(INT_MAX));
        int r = ssl ? SSL_read(ssl, p, chunk)
                    : ::recv(fd, reinterpret_cast<char *>(p), chunk, 0);
        if (r <= 0) return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

bool writeExact(SSL *ssl, SockFd fd, const void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes) return false;
    const auto *p = static_cast<const std::uint8_t *>(buf);
    while (n > 0)
    {
        int chunk = static_cast<int>(n < static_cast<std::size_t>(INT_MAX) ? n
                                                                            : static_cast<std::size_t>(INT_MAX));
        int r = ssl ? SSL_write(ssl, p, chunk)
                    : ::send(fd, reinterpret_cast<const char *>(p), chunk, 0);
        if (r <= 0) return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

SockFd connectToServer(const std::string &host, std::uint16_t port, std::string &errOut)
{
    // Use getaddrinfo (AF_UNSPEC) so that both hostnames and IP literals work,
    // and both IPv4 and IPv6 are supported. The old inet_pton path only accepted
    // IPv4 literals, silently failing on any hostname with "invalid server host".
    const std::string portStr = std::to_string(port);
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;    // accept IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = nullptr;
    const int gaiErr = ::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (gaiErr != 0 || !res)
    {
        // gai_strerrorA returns const char* on both ANSI and Unicode builds.
        errOut = "cannot resolve '" + host + "': " +
                 std::string{::gai_strerrorA(gaiErr)};
        return INVALID_SOCKET;
    }

    SOCKET fd = INVALID_SOCKET;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next)
    {
        fd = ::socket(rp->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCKET) continue;

        // Bound the TLS handshake and Ed25519 auth reads so a server that accepts
        // the connection but then stalls cannot hang the client thread (which would
        // also block connectionMutex_). On Windows SO_RCVTIMEO/SO_SNDTIMEO take a
        // DWORD of milliseconds; connect() itself uses the OS TCP connect timeout.
        {
            DWORD to = 30000;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char *>(&to), sizeof(to));
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                         reinterpret_cast<const char *>(&to), sizeof(to));
        }

        if (::connect(fd, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0)
            break;    // connected — stop trying further addresses

        ::closesocket(fd);
        fd = INVALID_SOCKET;
    }
    ::freeaddrinfo(res);

    if (fd == INVALID_SOCKET)
    {
        errOut = "connect to " + host + ":" + portStr +
                 " failed (WSA " + std::to_string(WSAGetLastError()) + ")";
        return INVALID_SOCKET;
    }
    return fd;
}

void setSendBufferSize(SockFd fd, int bytes)
{
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                 reinterpret_cast<const char *>(&bytes), sizeof(bytes));
}

// ---------------------------------------------------------------------------
// LAN address enumeration
// ---------------------------------------------------------------------------

std::unordered_set<std::string> collectLanAddresses()
{
    std::unordered_set<std::string> result;

    ULONG bufLen = 15000;
    std::vector<std::uint8_t> buf(bufLen);
    auto *addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.data());

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                    GAA_FLAG_SKIP_DNS_SERVER,
                    nullptr, addrs, &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        buf.resize(bufLen);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.data());
        ret = GetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                    GAA_FLAG_SKIP_DNS_SERVER,
                    nullptr, addrs, &bufLen);
    }
    if (ret != NO_ERROR) return result;

    char ipStr[INET6_ADDRSTRLEN];
    for (auto *adapter = addrs; adapter; adapter = adapter->Next)
    {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (auto *ua = adapter->FirstUnicastAddress; ua; ua = ua->Next)
        {
            auto *sa = ua->Address.lpSockaddr;
            if (sa->sa_family == AF_INET)
            {
                auto *sa4 = reinterpret_cast<struct sockaddr_in *>(sa);
                if (!isLanAddrV4(sa4->sin_addr.s_addr)) continue;
                if (::inet_ntop(AF_INET, &sa4->sin_addr, ipStr, sizeof(ipStr)))
                    result.insert(ipStr);
            }
            else if (sa->sa_family == AF_INET6)
            {
                auto *sa6 = reinterpret_cast<struct sockaddr_in6 *>(sa);
                if (!isLanAddrV6(sa6->sin6_addr.s6_addr)) continue;
                if (::inet_ntop(AF_INET6, &sa6->sin6_addr, ipStr, sizeof(ipStr)))
                    result.insert(ipStr);
            }
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// External IP (Winsock2 port of the POSIX socket version)
// ---------------------------------------------------------------------------

std::string queryExternalIP(const std::string &url, unsigned timeoutMs)
{
    if (url.size() < 8 || url.substr(0, 7) != "http://") return {};
    std::string rest = url.substr(7);
    auto slashPos = rest.find('/');
    std::string hostPort = (slashPos == std::string::npos) ? rest : rest.substr(0, slashPos);
    std::string path     = (slashPos == std::string::npos) ? "/" : rest.substr(slashPos);

    std::string host, portStr = "80";
    auto colonPos = hostPort.rfind(':');
    if (colonPos != std::string::npos)
    {
        host    = hostPort.substr(0, colonPos);
        portStr = hostPort.substr(colonPos + 1);
    }
    else host = hostPort;
    if (host.empty()) return {};

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) return {};

    SOCKET fd = ::socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) { ::freeaddrinfo(res); return {}; }

    // Non-blocking connect with select-based timeout
    u_long mode = 1;
    ::ioctlsocket(fd, FIONBIO, &mode);
    int cr = ::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen));
    ::freeaddrinfo(res);

    if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
    {
        ::closesocket(fd); return {};
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv{ static_cast<long>(timeoutMs / 1000),
                       static_cast<long>((timeoutMs % 1000) * 1000) };
    if (::select(0, nullptr, &wset, nullptr, &tv) <= 0)
    {
        ::closesocket(fd); return {};
    }
    int err = 0;
    int elen = sizeof(err);
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &elen);
    if (err != 0) { ::closesocket(fd); return {}; }

    // Restore blocking; set recv/send timeout
    mode = 0;
    ::ioctlsocket(fd, FIONBIO, &mode);
    DWORD tout = static_cast<DWORD>(timeoutMs);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&tout), sizeof(tout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&tout), sizeof(tout));

    std::string req = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (::send(fd, req.c_str(), static_cast<int>(req.size()), 0) == SOCKET_ERROR)
    {
        ::closesocket(fd); return {};
    }

    std::string response;
    response.reserve(512);
    char rbuf[512];
    int n;
    while ((n = ::recv(fd, rbuf, sizeof(rbuf), 0)) > 0)
    {
        response.append(rbuf, static_cast<std::size_t>(n));
        if (response.size() > 4096) break;
    }
    ::closesocket(fd);

    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return {};
    std::string body = response.substr(pos + 4);
    while (!body.empty() && (body.back() == '\r' || body.back() == '\n' ||
                              body.back() == ' '  || body.back() == '\t'))
        body.pop_back();
    auto bstart = body.find_first_not_of(" \r\n\t");
    if (bstart != std::string::npos && bstart > 0) body = body.substr(bstart);
    auto nl = body.find('\n');
    if (nl != std::string::npos && nl < 8) body = body.substr(nl + 1);
    while (!body.empty() && (body.back() == '\r' || body.back() == '\n' ||
                              body.back() == ' '  || body.back() == '\t'))
        body.pop_back();

    struct in_addr a4; struct in6_addr a6;
    if (::inet_pton(AF_INET,  body.c_str(), &a4) == 1 ||
        ::inet_pton(AF_INET6, body.c_str(), &a6) == 1)
        return body;
    return {};
}

// ---------------------------------------------------------------------------
// Loopback detection
// ---------------------------------------------------------------------------

bool isLoopbackIface(const pcap_if *dev)
{
    const auto *d = reinterpret_cast<const pcap_if_t *>(dev);
    if (!d) return false;
    // Npcap sets PCAP_IF_LOOPBACK for the NPF loopback adapter
    return (d->flags & PCAP_IF_LOOPBACK) != 0;
}

// ---------------------------------------------------------------------------
// Key file permissions — real Windows ACL check
// ---------------------------------------------------------------------------
// HARMONIZE-LINUX: this implements the Windows equivalent of the Linux
// stat()+mode check in src/client_linux.cpp:258-274. The threat model and
// policy (only owner + SYSTEM/Administrators may read) are intentionally
// identical; the APIs differ because Windows uses ACLs instead of POSIX modes.

void checkIdentityFilePermissions(const std::string &path, bool isDaemon, bool /*verbose*/)
{
    // Convert to wide string for Windows APIs.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return;
    std::wstring wpath(static_cast<std::size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);

    PSID               ownerSid  = nullptr;
    PACL               dacl      = nullptr;
    PSECURITY_DESCRIPTOR sd      = nullptr;
    DWORD ret = GetNamedSecurityInfoW(wpath.c_str(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    &ownerSid, nullptr, &dacl, nullptr, &sd);
    if (ret != ERROR_SUCCESS || !sd) return;  // file may not exist; silent return

    // Build SIDs for broad-access groups that should NOT have read access.
    struct {
        WELL_KNOWN_SID_TYPE type;
        const char *name;
    } broadSids[] = {
        { WinWorldSid,               "Everyone"           },
        { WinAuthenticatedUserSid,   "Authenticated Users" },
        { WinBuiltinUsersSid,        "BUILTIN\\Users"     },
        { WinInteractiveSid,         "Interactive"        },
    };

    auto warn = [&](const std::string &msg) {
        if (isDaemon) ntmLog(LogLevel::Warn, true, msg);
        else std::cerr << msg << "\n";
    };

    for (const auto &s : broadSids) {
        BYTE   sidBuf[SECURITY_MAX_SID_SIZE]{};
        DWORD  sidSize = sizeof(sidBuf);
        if (!CreateWellKnownSid(s.type, nullptr,
                                reinterpret_cast<PSID>(sidBuf), &sidSize))
            continue;
        TRUSTEE_W trustee{};
        trustee.TrusteeForm = TRUSTEE_IS_SID;
        trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        trustee.ptstrName   = reinterpret_cast<LPWCH>(sidBuf);
        ACCESS_MASK rights  = 0;
        if (GetEffectiveRightsFromAclW(dacl, &trustee, &rights) != ERROR_SUCCESS)
            continue;
        if (rights & (FILE_READ_DATA | GENERIC_READ | FILE_GENERIC_READ)) {
            warn("ntm-client: WARNING: identity key '" + path +
                 "' is readable by " + s.name + ".\n"
                 "  Fix: icacls \"" + path + "\" /inheritance:r /grant:r \"<current-user>:(R)\"");
        }
    }

    // Verify owner is the current user, LocalSystem, or Administrators.
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BYTE   tokenBuf[512]{};
        DWORD  needed = 0;
        if (GetTokenInformation(hToken, TokenUser, tokenBuf, sizeof(tokenBuf), &needed)) {
            auto *tu = reinterpret_cast<TOKEN_USER *>(tokenBuf);
            if (!EqualSid(ownerSid, tu->User.Sid)) {
                // Also accept LocalSystem (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544).
                BYTE localSystem[SECURITY_MAX_SID_SIZE]{};
                DWORD lsSize = sizeof(localSystem);
                BYTE admins[SECURITY_MAX_SID_SIZE]{};
                DWORD adSize = sizeof(admins);
                CreateWellKnownSid(WinLocalSystemSid,  nullptr,
                                   reinterpret_cast<PSID>(localSystem), &lsSize);
                CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                   reinterpret_cast<PSID>(admins), &adSize);
                if (!EqualSid(ownerSid, reinterpret_cast<PSID>(localSystem)) &&
                    !EqualSid(ownerSid, reinterpret_cast<PSID>(admins))) {
                    warn("ntm-client: WARNING: identity key '" + path +
                         "' is not owned by the current user or SYSTEM/Administrators.");
                }
            }
        }
        CloseHandle(hToken);
    }
    LocalFree(sd);
}

// ---------------------------------------------------------------------------
// Logging (stderr always — no syslog on Windows)
// ---------------------------------------------------------------------------

void ntmLog(LogLevel /*level*/, bool /*isDaemon*/, const std::string &msg)
{
    std::cerr << msg << "\n";
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static std::atomic<bool> *g_runningPtr = nullptr;

static BOOL WINAPI consoleCtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
    {
        if (g_runningPtr) g_runningPtr->store(false);
        return TRUE;
    }
    return FALSE;
}

void setupSignals(std::atomic<bool> &running)
{
    g_runningPtr = &running;
    ::SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
}

// ---------------------------------------------------------------------------
// Daemon (not supported on Windows)
// ---------------------------------------------------------------------------

void daemonize(bool isDaemon)
{
    if (isDaemon)
        std::cerr << "ntm-client: --daemon is not supported on Windows; running in foreground\n";
}

// ---------------------------------------------------------------------------
// Platform init/cleanup
// ---------------------------------------------------------------------------

void initPlatform()
{
    WSADATA wsa;
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "ntm-client: WSAStartup failed\n";
        std::exit(1);
    }
}

void cleanupPlatform()
{
    ::WSACleanup();
}

// ---------------------------------------------------------------------------
// NetworkMonitor — NotifyIpInterfaceChange with polling fallback
// ---------------------------------------------------------------------------

struct NetworkMonitor::Impl
{
    std::atomic<bool> running{false};
    std::atomic<bool> changed{false};
    std::thread       worker;
    HANDLE            notifyHandle{nullptr};

    static void NETIOAPI_API_ ifaceChangeCallback(PVOID ctx, PMIB_IPINTERFACE_ROW,
                                                  MIB_NOTIFICATION_TYPE)
    {
        auto *self = static_cast<Impl *>(ctx);
        self->changed.store(true);
    }

    void monitorLoopPoll()
    {
        auto prev = ntm::platform::collectLanAddresses();
        while (running.load())
        {
            for (int i = 0; i < 30 && running.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!running.load()) break;
            auto curr = ntm::platform::collectLanAddresses();
            if (curr != prev) { changed.store(true); prev = std::move(curr); }
        }
    }

    void monitorLoop()
    {
        HANDLE h = nullptr;
        DWORD ret = NotifyIpInterfaceChange(AF_UNSPEC, ifaceChangeCallback,
                                            this, FALSE, &h);
        if (ret != NO_ERROR)
        {
            monitorLoopPoll();
            return;
        }
        notifyHandle = h;
        // The callback fires on change; just keep the thread alive until stop()
        while (running.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

        CancelMibChangeNotify2(notifyHandle);
        notifyHandle = nullptr;
    }
};

NetworkMonitor::NetworkMonitor()  : impl_(std::make_unique<Impl>()) {}
NetworkMonitor::~NetworkMonitor() { stop(); }

void NetworkMonitor::start()
{
    if (impl_->running.exchange(true)) return;
    impl_->worker = std::thread(&Impl::monitorLoop, impl_.get());
}

void NetworkMonitor::stop()
{
    impl_->running.store(false);
    if (impl_->worker.joinable()) impl_->worker.join();
}

bool NetworkMonitor::checkAndClear()
{
    return impl_->changed.exchange(false);
}

} // namespace ntm::platform
