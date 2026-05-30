// client_transport_tcptls.cpp — TCP + TLS transport implementation.
//
// Extracted from ClientConnection::connectUnlocked() so that the transport
// mechanism is independently swappable (WebSocket, future QUIC, etc.) without
// touching the session-level auth and data-sending logic.

#include "client_transport_tcptls.hpp"
#include "client_core.hpp"          // verifyServerIdentityAndPin
#include "client_platform.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <poll.h>
#endif

namespace ntm
{

TcpTlsTransport::TcpTlsTransport(SSL_CTX    *sslCtx,
                                  std::string pinnedServerCertPath,
                                  bool        verbose,
                                  bool        isDaemon)
    : sslCtx_(sslCtx)
    , pinnedServerCertPath_(std::move(pinnedServerCertPath))
    , verbose_(verbose)
    , isDaemon_(isDaemon)
{}

TcpTlsTransport::~TcpTlsTransport()
{
    close();
}

bool TcpTlsTransport::connect(const std::string &host, std::uint16_t port,
                               std::string &errOut)
{
    if (isConnected()) return true;   // already up

    auto logInfo = [&](const std::string &msg) {
        if (verbose_) platform::ntmLog(platform::LogLevel::Info, isDaemon_, msg);
    };
    auto logErr = [&](const std::string &msg) {
        platform::ntmLog(platform::LogLevel::Err, isDaemon_, msg);
    };

    // ── 1. TCP connect ───────────────────────────────────────────────────────
    logInfo("ntm-client: [connect] attempting TCP connect to "
            + host + ":" + std::to_string(port));

    platform::SockFd fd = platform::connectToServer(host, port, errOut);
    if (!platform::sockValid(fd))
    {
        logErr("ntm-client: [connect] TCP connect failed: " + errOut);
        return false;
    }
    logInfo("ntm-client: [connect] TCP connection established");

    platform::setSendBufferSize(fd, 4 * 1024 * 1024);

    // ── 2. TLS handshake ─────────────────────────────────────────────────────
    SSL *ssl = nullptr;
    if (sslCtx_)
    {
        ssl = SSL_new(sslCtx_);
        if (!ssl)
        {
            errOut = "SSL_new failed";
            platform::closeSocket(fd);
            return false;
        }

        // SNI: only for DNS hostnames, not IP literals (RFC 6066).
        {
            unsigned char ipBuf[16];
            const bool isIp = (::inet_pton(AF_INET,  host.c_str(), ipBuf) == 1) ||
                              (::inet_pton(AF_INET6, host.c_str(), ipBuf) == 1);
            if (!isIp)
            {
                SSL_set_tlsext_host_name(ssl, host.c_str());
                logInfo("ntm-client: [connect] TLS SNI set to: " + host);
            }
            else
                logInfo("ntm-client: [connect] TLS SNI skipped (IP literal)");
        }

#ifdef _WIN32
        SSL_set_fd(ssl, static_cast<int>(fd));
#else
        SSL_set_fd(ssl, fd);
#endif

        logInfo("ntm-client: [connect] starting TLS handshake (ALPN offered: ntm-wire)...");
        if (SSL_connect(ssl) != 1)
        {
            char errBuf[256];
            unsigned long opensslErr;
            std::string errChain;
            while ((opensslErr = ERR_get_error()) != 0)
            {
                ERR_error_string_n(opensslErr, errBuf, sizeof(errBuf));
                if (!errChain.empty()) errChain += "; ";
                errChain += errBuf;
            }
            errOut = "TLS handshake failed";
            logErr("ntm-client: [connect] TLS handshake FAILED"
                   + (errChain.empty() ? "" : ": " + errChain));
            SSL_free(ssl);
            platform::closeSocket(fd);
            return false;
        }

        // Log negotiated TLS details.  ALPN != "ntm-wire" means an HTTP proxy
        // (e.g. Cloudflare) is in the path — warn but continue; the WebSocket
        // transport won't hit this path at all.
        if (verbose_)
        {
            const char *tlsVer = SSL_get_version(ssl);
            const char *cipher  = SSL_get_cipher(ssl);
            const unsigned char *alpnData = nullptr;
            unsigned int alpnLen = 0;
            SSL_get0_alpn_selected(ssl, &alpnData, &alpnLen);
            std::string alpn = alpnLen
                ? std::string(reinterpret_cast<const char *>(alpnData), alpnLen)
                : "(none)";
            logInfo(std::string("ntm-client: [connect] TLS handshake ok: ")
                    + (tlsVer ? tlsVer : "?") + " / " + (cipher ? cipher : "?")
                    + " / ALPN=" + alpn);
            if (alpn != "ntm-wire")
                platform::ntmLog(platform::LogLevel::Warn, isDaemon_,
                    "ntm-client: [connect] WARNING — server selected ALPN='" + alpn
                    + "' not 'ntm-wire'. Connection may be through an HTTP proxy. "
                    "Use transport=websocket to traverse Cloudflare.");
        }

        // ── 3. Server identity verification ──────────────────────────────────
        logInfo("ntm-client: [connect] verifying server identity...");
        if (!verifyServerIdentityAndPin(ssl, host, pinnedServerCertPath_,
                                        verbose_, isDaemon_))
        {
            errOut = "server identity verification failed";
            logErr("ntm-client: [connect] server identity verification FAILED");
            SSL_free(ssl);
            platform::closeSocket(fd);
            return false;
        }
    }
    else
    {
        logInfo("ntm-client: [connect] WARNING — no TLS context; connecting in plaintext");
    }

    fd_  = fd;
    ssl_ = ssl;
    return true;
}

void TcpTlsTransport::close()
{
    if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
    if (platform::sockValid(fd_)) { platform::closeSocket(fd_); fd_ = platform::kInvalidSock; }
}

bool TcpTlsTransport::isConnected() const
{
    return platform::sockValid(fd_);
}

bool TcpTlsTransport::readExact(void *buf, std::size_t n)
{
    return platform::readExact(ssl_, fd_, buf, n);
}

bool TcpTlsTransport::writeExact(const void *buf, std::size_t n)
{
    return platform::writeExact(ssl_, fd_, buf, n);
}

bool TcpTlsTransport::pollCtrlLines(std::string &inBuf, std::vector<std::string> &out)
{
    if (!ssl_ || !platform::sockValid(fd_)) return false;

    // Check if there is any server→client data ready without blocking.
    bool hasPending = SSL_has_pending(ssl_) > 0;
    if (!hasPending)
    {
#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd     = fd_;
        pfd.events = POLLRDNORM;
        if (::WSAPoll(&pfd, 1, 0) <= 0) return true;
        hasPending = (pfd.revents & POLLRDNORM) != 0;
#else
        struct pollfd pfd{};
        pfd.fd     = static_cast<int>(fd_);
        pfd.events = POLLIN;
        if (::poll(&pfd, 1, 0) <= 0) return true;
        hasPending = (pfd.revents & POLLIN) != 0;
#endif
    }
    if (!hasPending) return true;

    // Data available: read one chunk and append to inBuf.
    char buf[4096];
    const int r = SSL_read(ssl_, buf, static_cast<int>(sizeof(buf)));
    if (r > 0)
    {
        inBuf.append(buf, static_cast<std::size_t>(r));
    }
    else
    {
        const int err = SSL_get_error(ssl_, r);
        ERR_clear_error();
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return true;
        return false;
    }

    // Extract complete newline-terminated lines from inBuf.
    std::size_t pos = 0;
    while (true)
    {
        const std::size_t nl = inBuf.find('\n', pos);
        if (nl == std::string::npos) break;
        std::string line = inBuf.substr(pos, nl - pos);
        while (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(std::move(line));
        pos = nl + 1;
    }
    if (pos > 0) inBuf.erase(0, pos);
    return true;
}

} // namespace ntm
