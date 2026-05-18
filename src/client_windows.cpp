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
    SOCKET fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET)
    {
        errOut = "socket() failed (WSA " + std::to_string(WSAGetLastError()) + ")";
        return INVALID_SOCKET;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        errOut = "invalid server host: " + host;
        ::closesocket(fd);
        return INVALID_SOCKET;
    }
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
    {
        errOut = "connect() failed (WSA " + std::to_string(WSAGetLastError()) + ")";
        ::closesocket(fd);
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
// Key file permissions (stub — full Windows ACL check is a future enhancement)
// ---------------------------------------------------------------------------

void checkIdentityFilePermissions(const std::string &path, bool /*isDaemon*/, bool /*verbose*/)
{
    // On Windows, permission checking requires the Security API.
    // We emit a reminder to protect the file via NTFS permissions manually.
    std::cerr << "ntm-client: NOTE: ensure identity key is protected via NTFS permissions: "
              << path << "\n";
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
