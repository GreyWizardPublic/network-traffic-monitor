#if !defined(__linux__)
#error "client_linux.cpp is only for Linux builds"
#endif

#include "client_platform.hpp"
#include "client_core.hpp"
#include "client_http_util.hpp"

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>

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
                    : static_cast<int>(::recv(fd, p, static_cast<std::size_t>(chunk), 0));
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
                    : static_cast<int>(::send(fd, p, static_cast<std::size_t>(chunk), MSG_NOSIGNAL));
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
    // Use getaddrinfo so the caller can specify either a hostname ("my.server.com")
    // or a bare IPv4/IPv6 literal — the previous inet_pton-only path rejected any
    // hostname, making DNS-based server addresses (e.g. via Cloudflare or any other
    // domain) silently fail with "invalid server host".
    // AF_UNSPEC lets getaddrinfo return both IPv4 and IPv6 results; we try each in
    // order and use the first that connects successfully.
    const std::string portStr = std::to_string(port);
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;    // accept IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = nullptr;
    const int gaiErr = ::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (gaiErr != 0 || !res)
    {
        errOut = "cannot resolve '" + host + "': " + ::gai_strerror(gaiErr);
        return kInvalidSock;
    }

    SockFd fd = kInvalidSock;
    for (const struct addrinfo *rp = res; rp; rp = rp->ai_next)
    {
        fd = ::socket(rp->ai_family, SOCK_STREAM, 0);
        if (fd < 0) continue;

        // Bound connect(), the TLS handshake and the Ed25519 auth exchange so a
        // dead or malicious server that accepts TCP but never replies cannot hang
        // the client thread indefinitely (which would also block connectionMutex_).
        // On Linux SO_SNDTIMEO bounds a blocking connect(); SO_RCVTIMEO bounds
        // the subsequent handshake/auth reads.
        {
            struct timeval tv{ 30, 0 };
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;        // connected on this address — stop trying

        ::close(fd);
        fd = kInvalidSock;
    }
    ::freeaddrinfo(res);

    if (fd < 0)
    {
        errOut = "connect to " + host + ":" + portStr + " failed: " + std::strerror(errno);
        return kInvalidSock;
    }
    return fd;
}

void setSendBufferSize(SockFd fd, int bytes)
{
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) < 0)
        std::perror("setsockopt(SO_SNDBUF)");
}

// ---------------------------------------------------------------------------
// LAN address enumeration
// ---------------------------------------------------------------------------

std::unordered_set<std::string> collectLanAddresses()
{
    std::unordered_set<std::string> result;
    struct ifaddrs *ifap = nullptr;
    if (::getifaddrs(&ifap) != 0) return result;
    char buf[INET6_ADDRSTRLEN];
    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            auto *sa4 = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
            if (!isLanAddrV4(sa4->sin_addr.s_addr)) continue;
            if (!::inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf))) continue;
            result.insert(buf);
        }
        else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            auto *sa6 = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
            if (!isLanAddrV6(sa6->sin6_addr.s6_addr)) continue;
            if (!::inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf))) continue;
            result.insert(buf);
        }
    }
    ::freeifaddrs(ifap);
    return result;
}

// ---------------------------------------------------------------------------
// External IP
// ---------------------------------------------------------------------------

std::string queryExternalIP(const std::string &url, unsigned timeoutMs)
{
    auto parsed = http_util::parseHttpUrl(url);
    if (!parsed.ok) return {};
    const std::string &host    = parsed.host;
    const std::string &portStr = parsed.port;
    const std::string &path    = parsed.path;

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) return {};

    int fd = ::socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { ::freeaddrinfo(res); return {}; }

    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int cr = ::connect(fd, res->ai_addr, res->ai_addrlen);
    ::freeaddrinfo(res);

    if (cr != 0 && errno != EINPROGRESS) { ::close(fd); return {}; }
    if (cr != 0)
    {
        struct pollfd pfd{fd, POLLOUT, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(timeoutMs));
        if (pr <= 0) { ::close(fd); return {}; }
        int err = 0; socklen_t elen = sizeof(err);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) { ::close(fd); return {}; }
    }
    ::fcntl(fd, F_SETFL, flags);
    struct timeval tv{ static_cast<time_t>(timeoutMs / 1000),
                       static_cast<suseconds_t>((timeoutMs % 1000) * 1000) };
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string req = http_util::buildGetRequest(path, host);
    if (::send(fd, req.c_str(), req.size(), MSG_NOSIGNAL) < 0) { ::close(fd); return {}; }

    std::string response;
    response.reserve(512);
    char rbuf[512];
    ssize_t n;
    while ((n = ::recv(fd, rbuf, sizeof(rbuf), 0)) > 0)
    {
        response.append(rbuf, static_cast<std::size_t>(n));
        if (response.size() > 4096) break;
    }
    ::close(fd);

    std::string body = http_util::extractHttpBody(response);

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
    if (d->flags & PCAP_IF_LOOPBACK) return true;
    return d->name && std::strcmp(d->name, "lo") == 0;
}

// ---------------------------------------------------------------------------
// Key file permissions
// ---------------------------------------------------------------------------

void checkIdentityFilePermissions(const std::string &path, bool isDaemon, bool /*verbose*/)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return;
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        const char *msg = "ntm-client: WARNING: identity key has group/world permissions";
        if (isDaemon) syslog(LOG_WARNING, "%s (path=%s)", msg, path.c_str());
        else std::cerr << msg << " (path=" << path << ")\n";
    }
    if (st.st_uid != ::geteuid())
    {
        const char *msg = "ntm-client: WARNING: identity key not owned by current user";
        if (isDaemon) syslog(LOG_WARNING, "%s (path=%s)", msg, path.c_str());
        else std::cerr << msg << " (path=" << path << ")\n";
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

void ntmLog(LogLevel level, bool isDaemon, const std::string &msg)
{
    if (isDaemon)
    {
        int prio = (level == LogLevel::Err)  ? LOG_ERR
                 : (level == LogLevel::Warn) ? LOG_WARNING
                 : LOG_INFO;
        syslog(prio, "%s", msg.c_str());
    }
    else
    {
        std::cerr << msg << "\n";
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static std::atomic<bool> *g_runningPtr = nullptr;

static void sigHandler(int) { if (g_runningPtr) g_runningPtr->store(false); }

void setupSignals(std::atomic<bool> &running)
{
    g_runningPtr = &running;
    std::signal(SIGINT,  sigHandler);
    std::signal(SIGTERM, sigHandler);
}

void requestStop() {}  // Linux uses signals; this path is only called on Windows

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

void daemonize(bool isDaemon)
{
    if (!isDaemon) return;

    pid_t pid = ::fork();
    if (pid < 0) { std::perror("fork"); std::exit(EXIT_FAILURE); }
    if (pid > 0) std::exit(EXIT_SUCCESS);
    if (::setsid() < 0) { std::perror("setsid"); std::exit(EXIT_FAILURE); }
    pid = ::fork();
    if (pid < 0) { std::perror("fork"); std::exit(EXIT_FAILURE); }
    if (pid > 0) std::exit(EXIT_SUCCESS);
    ::umask(0);
    if (::chdir("/") != 0) std::perror("chdir");
    int fd = ::open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        ::dup2(fd, STDIN_FILENO);
        ::dup2(fd, STDOUT_FILENO);
        ::dup2(fd, STDERR_FILENO);
        if (fd > 2) ::close(fd);
    }
}

// ---------------------------------------------------------------------------
// Platform init/cleanup (no-op on Linux)
// ---------------------------------------------------------------------------

void initPlatform()  {}
void cleanupPlatform() {}

// ---------------------------------------------------------------------------
// NetworkMonitor — RTNETLINK with getifaddrs fallback
// ---------------------------------------------------------------------------

struct NetworkMonitor::Impl
{
    std::atomic<bool> running{false};
    std::atomic<bool> changed{false};
    std::thread       worker;

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
        int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) { monitorLoopPoll(); return; }

        struct sockaddr_nl sa{};
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        if (::bind(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) < 0)
        {
            ::close(fd);
            monitorLoopPoll();
            return;
        }

        char buf[4096];
        while (running.load())
        {
            struct pollfd pfd{fd, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 1000);
            if (pr < 0) { if (errno == EINTR) continue; break; }
            if (pr == 0) continue;

            ssize_t len = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (len < 0) continue;

            for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
                 len > 0 && NLMSG_OK(nh, static_cast<unsigned>(len));
                 nh = NLMSG_NEXT(nh, len))
            {
                if (nh->nlmsg_type == NLMSG_DONE) break;
                switch (nh->nlmsg_type)
                {
                case RTM_NEWADDR: case RTM_DELADDR:
                case RTM_NEWLINK: case RTM_DELLINK:
                    changed.store(true); break;
                default: break;
                }
            }
        }
        ::close(fd);
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
