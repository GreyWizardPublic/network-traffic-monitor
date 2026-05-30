#pragma once

// client_transport_websocket.hpp — WebSocket transport for ntm-client.
//
// Wraps an underlying TcpTlsTransport and runs an RFC 6455 WebSocket upgrade
// on connect(), then frames all subsequent I/O as WebSocket binary data frames.
//
// This transport allows the ntm-client to traverse Cloudflare and other HTTP
// reverse proxies that terminate TLS and forward only HTTP/WebSocket traffic.
// The ntm-wire auth + data protocol bytes are completely unchanged; they are
// simply wrapped in WebSocket frames instead of sent over raw TLS.

#include "client_transport.hpp"
#include "client_transport_tcptls.hpp"
#include "client_websocket.hpp"

#include <openssl/ssl.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ntm
{

class WebSocketTransport final : public ITransport
{
public:
    // sslCtx is borrowed (not owned).
    WebSocketTransport(SSL_CTX    *sslCtx,
                       std::string pinnedServerCertPath,
                       bool        verbose,
                       bool        isDaemon);

    ~WebSocketTransport() override;

    // ITransport
    bool connect(const std::string &host, std::uint16_t port,
                 std::string &errOut) override;
    void close() override;
    bool isConnected() const override;
    bool readExact(void *buf, std::size_t n) override;
    bool writeExact(const void *buf, std::size_t n) override;
    SSL *sslHandle() const override;
    bool pollCtrlLines(std::string &inBuf, std::vector<std::string> &out) override;

private:
    std::unique_ptr<TcpTlsTransport> tcp_;

    // WebSocket frame reader (parses incoming frames, buffers payload bytes).
    ws::FrameReader                 reader_;

    // Payload bytes already extracted from frames, not yet consumed by readExact.
    std::vector<std::uint8_t>       readBuf_;
    std::size_t                     readBufPos_{0};

    // Parameters saved for the TcpTlsTransport
    SSL_CTX    *sslCtx_;
    std::string pinnedServerCertPath_;
    bool        verbose_;
    bool        isDaemon_;

    // Perform the HTTP/1.1 → WebSocket upgrade handshake.
    // Returns false and sets errOut on any failure.
    bool doHandshake(const std::string &host, std::string &errOut);

    // Fill readBuf_ from at least one incoming WebSocket frame.
    // Returns false if the underlying connection failed.
    bool fillReadBuf();
};

} // namespace ntm
