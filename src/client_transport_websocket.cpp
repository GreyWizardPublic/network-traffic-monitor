// client_transport_websocket.cpp — WebSocket transport implementation.

#include "client_transport_websocket.hpp"
#include "client_platform.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <poll.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace ntm
{

// ---------------------------------------------------------------------------
// OpenSSL helpers (base64 + SHA-1) — local to this TU
// ---------------------------------------------------------------------------

// Base64-encode src (srcLen bytes) into a std::string.
static std::string base64Encode(const unsigned char *src, int srcLen)
{
    // EVP_EncodeBlock output size: 4 * ceil(srcLen/3) + 1 (for NUL).
    int outLen = ((srcLen + 2) / 3) * 4;
    std::vector<unsigned char> buf(static_cast<std::size_t>(outLen) + 1, 0);
    int actual = EVP_EncodeBlock(buf.data(), src, srcLen);
    return std::string(reinterpret_cast<const char *>(buf.data()),
                       static_cast<std::size_t>(actual));
}

// Compute Sec-WebSocket-Accept from Sec-WebSocket-Key (RFC 6455 §1.3).
static std::string computeAccept(const std::string &key)
{
    std::string input = key + ws::kWsGuid;
    unsigned char sha1[SHA_DIGEST_LENGTH];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    SHA1(reinterpret_cast<const unsigned char *>(input.data()),
         input.size(), sha1);
#pragma GCC diagnostic pop
    return base64Encode(sha1, SHA_DIGEST_LENGTH);
}

// Generate a random 16-byte Sec-WebSocket-Key (base64-encoded).
static std::string generateKey()
{
    unsigned char bytes[16];
    RAND_bytes(bytes, static_cast<int>(sizeof(bytes)));
    return base64Encode(bytes, static_cast<int>(sizeof(bytes)));
}

// Generate a 4-byte WebSocket masking key.
static std::array<std::uint8_t, 4> generateMaskKey()
{
    std::array<std::uint8_t, 4> key{};
    RAND_bytes(key.data(), 4);
    return key;
}

// ---------------------------------------------------------------------------
// Read exactly n bytes from the underlying TcpTlsTransport into dst.
// Used only during the HTTP upgrade handshake (before WebSocket framing).
// ---------------------------------------------------------------------------
static bool tcpReadExact(TcpTlsTransport *tcp, void *dst, std::size_t n)
{
    return tcp->readExact(dst, n);
}

// Read the server's HTTP response up to and including the blank line.
// Stops after "\r\n\r\n". Returns empty string on I/O error.
static std::string readHttpResponse(TcpTlsTransport *tcp)
{
    std::string response;
    response.reserve(512);
    char c = 0;
    while (response.size() < 8192)   // guard against pathological servers
    {
        if (!tcpReadExact(tcp, &c, 1)) return {};
        response.push_back(c);
        if (response.size() >= 4 &&
            response.substr(response.size() - 4) == "\r\n\r\n")
            break;
    }
    return response;
}

// ---------------------------------------------------------------------------
// WebSocketTransport
// ---------------------------------------------------------------------------

WebSocketTransport::WebSocketTransport(SSL_CTX    *sslCtx,
                                        std::string pinnedServerCertPath,
                                        bool        verbose,
                                        bool        isDaemon)
    : sslCtx_(sslCtx)
    , pinnedServerCertPath_(std::move(pinnedServerCertPath))
    , verbose_(verbose)
    , isDaemon_(isDaemon)
{}

WebSocketTransport::~WebSocketTransport()
{
    close();
}

bool WebSocketTransport::connect(const std::string &host, std::uint16_t port,
                                  std::string &errOut)
{
    if (isConnected()) return true;

    // Create a fresh TcpTlsTransport for the underlying TCP + TLS connection.
    // We pass pinnedServerCertPath_ so the TLS layer still verifies the cert.
    tcp_ = std::make_unique<TcpTlsTransport>(
        sslCtx_, pinnedServerCertPath_, verbose_, isDaemon_);

    if (!tcp_->connect(host, port, errOut))
        return false;

    if (!doHandshake(host, errOut))
    {
        tcp_->close();
        tcp_.reset();
        return false;
    }

    return true;
}

bool WebSocketTransport::doHandshake(const std::string &host, std::string &errOut)
{
    auto logInfo = [&](const std::string &msg) {
        if (verbose_) platform::ntmLog(platform::LogLevel::Info, isDaemon_, msg);
    };

    const std::string key      = generateKey();
    const std::string expected = computeAccept(key);

    const std::string req = ws::buildUpgradeRequest(host, key);
    logInfo("ntm-client: [ws] sending WebSocket upgrade request to " +
            std::string(ws::kWsPath));

    if (!tcp_->writeExact(req.data(), req.size()))
    {
        errOut = "WebSocket upgrade request write failed";
        return false;
    }

    const std::string response = readHttpResponse(tcp_.get());
    if (response.empty())
    {
        errOut = "WebSocket upgrade: no response from server";
        return false;
    }

    std::string serverAccept;
    if (!ws::parseUpgradeResponse(response, serverAccept, errOut))
        return false;

    if (serverAccept != expected)
    {
        errOut = "WebSocket Sec-WebSocket-Accept mismatch (expected=" + expected
               + " got=" + serverAccept + ")";
        return false;
    }

    logInfo("ntm-client: [ws] WebSocket handshake complete");
    return true;
}

void WebSocketTransport::close()
{
    if (tcp_) { tcp_->close(); tcp_.reset(); }
    readBuf_.clear();
    readBufPos_ = 0;
}

bool WebSocketTransport::isConnected() const
{
    return tcp_ && tcp_->isConnected();
}

SSL *WebSocketTransport::sslHandle() const
{
    return tcp_ ? tcp_->sslHandle() : nullptr;
}

bool WebSocketTransport::fillReadBuf()
{
    // Read one network chunk at a time, feed into the frame parser.
    // Keep reading until we have at least one payload byte buffered.
    std::array<std::uint8_t, 4096> tmp{};
    while (true)
    {
        // Compact readBuf_ if the read position is past the half-way point.
        if (readBufPos_ > 0 && readBufPos_ >= readBuf_.size())
        {
            readBuf_.clear();
            readBufPos_ = 0;
        }

        if (reader_.available() > 0)
        {
            // Drain newly parsed payload into readBuf_.
            std::size_t n = reader_.take(tmp.data(), tmp.size());
            readBuf_.insert(readBuf_.end(), tmp.data(), tmp.data() + n);
            if (readBuf_.size() > readBufPos_) return true;
        }

        // Read raw bytes from the underlying TLS stream.
        // We read just one byte to advance the state machine; larger reads
        // are more efficient but complicate partial-frame handling.
        // In practice, the kernel batches data and this is called infrequently.
        std::uint8_t raw[256];
        // Use a chunked read: try to get up to 256 bytes at once.
        // platform::readExact would block until all bytes arrive; instead we
        // need a non-blocking-style read.  We achieve this by calling SSL_read
        // (or recv) once and accepting a partial result.
        // Since ITransport::readExact is exact-read only, we temporarily read
        // 1 byte at a time to avoid blocking when a frame boundary falls mid-
        // buffer.  For the data phase (large D-line batches) the frame reader
        // quickly accumulates enough bytes for the readExact call above.
        if (!tcp_->readExact(raw, 1)) return false;
        reader_.feed(raw, 1);
    }
}

bool WebSocketTransport::readExact(void *buf, std::size_t n)
{
    auto *dst = static_cast<std::uint8_t *>(buf);
    std::size_t remaining = n;

    while (remaining > 0)
    {
        std::size_t inBuf = (readBuf_.size() > readBufPos_)
                          ? (readBuf_.size() - readBufPos_)
                          : 0;

        if (inBuf == 0)
        {
            if (!fillReadBuf()) return false;
            continue;
        }

        std::size_t take = (remaining < inBuf) ? remaining : inBuf;
        std::memcpy(dst, readBuf_.data() + readBufPos_, take);
        dst         += take;
        readBufPos_ += take;
        remaining   -= take;
    }
    return true;
}

bool WebSocketTransport::writeExact(const void *buf, std::size_t n)
{
    if (n == 0) return true;

    const auto maskKey = generateMaskKey();
    auto frame = ws::buildClientFrame(buf, n, maskKey.data());
    return tcp_->writeExact(frame.data(), frame.size());
}

bool WebSocketTransport::pollCtrlLines(std::string &inBuf, std::vector<std::string> &out)
{
    if (!tcp_ || !tcp_->isConnected()) return false;

    // If there are already decoded payload bytes in the read buffer, use them.
    bool hasBuffered = readBufPos_ < readBuf_.size();
    if (!hasBuffered)
    {
        // Check if the underlying SSL has pending/readable data before trying to fill.
        SSL *ssl = tcp_->sslHandle();
        if (!ssl) return false;

        bool hasPending = SSL_has_pending(ssl) > 0;
        if (!hasPending)
        {
            const int fd = SSL_get_fd(ssl);
            if (fd < 0) return false;
#ifdef _WIN32
            WSAPOLLFD pfd{};
            pfd.fd     = static_cast<SOCKET>(fd);
            pfd.events = POLLRDNORM;
            if (::WSAPoll(&pfd, 1, 0) <= 0) return true;
            hasPending = (pfd.revents & POLLRDNORM) != 0;
#else
            struct pollfd pfd{};
            pfd.fd     = fd;
            pfd.events = POLLIN;
            if (::poll(&pfd, 1, 0) <= 0) return true;
            hasPending = (pfd.revents & POLLIN) != 0;
#endif
        }
        if (!hasPending) return true;

        // Read one SSL chunk and feed it to the WS frame parser.
        std::uint8_t raw[4096];
        const int r = SSL_read(ssl, raw, static_cast<int>(sizeof(raw)));
        if (r > 0)
        {
            reader_.feed(raw, static_cast<std::size_t>(r));
        }
        else
        {
            const int err = SSL_get_error(ssl, r);
            ERR_clear_error();
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                return true;
            return false;
        }

        // Drain decoded payload bytes into readBuf_.
        if (reader_.available() > 0)
        {
            std::array<std::uint8_t, 4096> tmp{};
            const std::size_t n = reader_.take(tmp.data(), tmp.size());
            if (readBufPos_ > 0 && readBufPos_ >= readBuf_.size())
            {
                readBuf_.clear();
                readBufPos_ = 0;
            }
            readBuf_.insert(readBuf_.end(), tmp.data(), tmp.data() + n);
        }
    }

    // Extract complete newline-terminated lines from readBuf_.
    while (readBufPos_ < readBuf_.size())
    {
        const auto *data  = readBuf_.data() + readBufPos_;
        const std::size_t avail = readBuf_.size() - readBufPos_;
        const auto *nlPtr = static_cast<const std::uint8_t *>(std::memchr(data, '\n', avail));
        if (!nlPtr) break;
        const std::size_t lineLen = static_cast<std::size_t>(nlPtr - data);
        std::string line(reinterpret_cast<const char *>(data), lineLen);
        while (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(std::move(line));
        readBufPos_ += lineLen + 1;
    }
    (void)inBuf;  // WebSocket uses its own readBuf_; inBuf is unused for this transport
    return true;
}

} // namespace ntm
