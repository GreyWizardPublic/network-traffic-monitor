#pragma once

// client_transport_tcptls.hpp — Raw TCP + TLS transport.
//
// Implements ITransport using a plain TCP socket upgraded to TLS via OpenSSL.
// This is the original ntm-client connection path: ALPN "ntm-wire" is offered
// so the server can multiplex wire clients and HTTPS browsers on one port.
//
// connect() encapsulates:
//   1. DNS resolution + TCP connect (via platform::connectToServer)
//   2. TLS handshake with SNI
//   3. ALPN negotiation + warning if server chose a proxy-imposed protocol
//   4. Server identity verification (CA chain or cert pinning)

#include "client_transport.hpp"
#include "client_platform.hpp"

#include <openssl/ssl.h>
#include <cstdint>
#include <string>

namespace ntm
{

class TcpTlsTransport final : public ITransport
{
public:
    // sslCtx is borrowed (not owned); the caller must keep it alive for the
    // lifetime of this object.  Pass nullptr for a plain (non-TLS) connection
    // (only used in tests; the production client always requires TLS).
    TcpTlsTransport(SSL_CTX    *sslCtx,
                    std::string pinnedServerCertPath,
                    bool        verbose,
                    bool        isDaemon);

    ~TcpTlsTransport() override;

    // ITransport
    bool connect(const std::string &host, std::uint16_t port,
                 std::string &errOut) override;
    void close() override;
    bool isConnected() const override;
    bool readExact(void *buf, std::size_t n) override;
    bool writeExact(const void *buf, std::size_t n) override;
    SSL *sslHandle() const override { return ssl_; }

private:
    SSL_CTX              *sslCtx_;
    std::string           pinnedServerCertPath_;
    bool                  verbose_;
    bool                  isDaemon_;
    platform::SockFd      fd_{platform::kInvalidSock};
    SSL                  *ssl_{nullptr};
};

} // namespace ntm
