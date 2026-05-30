#pragma once

// client_transport.hpp — Transport abstraction for the ntm-client wire session.
//
// ITransport decouples the connection/auth/data logic in ClientConnection from
// the concrete wire mechanism.  Two implementations exist:
//
//   TcpTlsTransport     — raw TCP + TLS with "ntm-wire" ALPN (current behaviour).
//   WebSocketTransport  — HTTP/1.1 WebSocket upgrade over TLS (Cloudflare-compatible).
//
// Adding a new transport (e.g. QUIC) only requires a new ITransport subclass
// and a factory case in connectUnlocked(); the session logic is unchanged.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Forward-declare SSL so headers that include this file need not pull in OpenSSL.
typedef struct ssl_st SSL;

namespace ntm
{

class ITransport
{
public:
    virtual ~ITransport() = default;

    // ---------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------

    // Establish the connection to host:port.  Returns false and populates errOut
    // on any failure (DNS, TCP connect, TLS handshake, server identity check).
    virtual bool connect(const std::string &host, std::uint16_t port,
                         std::string &errOut) = 0;

    // Gracefully close the connection (TLS shutdown + socket close).
    // Safe to call on a transport that is already closed.
    virtual void close() = 0;

    // True if the transport currently has an active connection.
    virtual bool isConnected() const = 0;

    // ---------------------------------------------------------------------------
    // I/O
    // ---------------------------------------------------------------------------

    // Read exactly n bytes from the connection into buf.
    // Returns false on any error (timeout, peer close, I/O error).
    virtual bool readExact(void *buf, std::size_t n) = 0;

    // Write exactly n bytes from buf to the connection.
    // Returns false on any error.
    virtual bool writeExact(const void *buf, std::size_t n) = 0;

    // ---------------------------------------------------------------------------
    // TLS introspection (for verifyServerIdentityAndPin)
    // ---------------------------------------------------------------------------

    // Return the underlying OpenSSL SSL object, or nullptr if the connection
    // is not TLS (plain TCP).  Used by verifyServerIdentityAndPin() which needs
    // direct SSL handle access for certificate inspection.
    virtual SSL *sslHandle() const = 0;

    // Wire-proto v3: non-blocking poll for incoming server→client lines (C-lines).
    // Appends any available bytes to inBuf, then extracts complete newline-terminated
    // lines into out.  Returns false on hard error (caller should close transport).
    // Returns true with an empty out if no complete lines are available yet.
    // Default no-op: transports that never receive server-initiated data return true.
    virtual bool pollCtrlLines(std::string & /*inBuf*/,
                               std::vector<std::string> & /*out*/) { return true; }
};

} // namespace ntm
