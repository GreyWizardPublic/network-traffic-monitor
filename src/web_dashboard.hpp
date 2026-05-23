#pragma once

// web_dashboard.hpp — HTTPS dashboard interface.
// Add new web config knobs to WebConfig; add new endpoints in web_dashboard.cpp.
// server_core populates WebConfig from ServerConfig at thread-launch time.

#include "ntm_types.hpp"
#include "webauthn.hpp"

// httplib requires this macro to compile TLS support (OpenSSL backend).
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

namespace ntm
{

// Configuration subset the web dashboard needs.
// Populated from ServerConfig in runServer(); the web side never sees ServerConfig.
struct WebConfig
{
    std::uint16_t port{8443};
    std::string   bind{"0.0.0.0"};
    unsigned      rate_limit_rpm{30};
    std::size_t   max_entity_lines{50000};
    // Display-time nickname substitution: lowercase 64-hex pubkey → human-readable name.
    // The internal clientId in TrafficStats is always the raw hex; lookup happens only at
    // JSON serialisation so renaming a client never orphans historical data.
    std::unordered_map<std::string, std::string> client_nicknames;
    // Shared registry for per-client health stats (pcap / send-buffer drop counters).
    // Null = health section omitted from the API response.
    std::shared_ptr<ClientRegistry> registry;

    // WebAuthn RP (null = WebAuthn disabled; LAN-only access used instead).
    std::shared_ptr<WebAuthnRP> webauthn;
    // Shared wire-protocol client store; null = registration endpoint disabled.
    std::shared_ptr<AllowedClientsStore> clients_store;

    // Directory containing operator-placed client update binaries.
    // Empty = auto-update endpoints disabled.
    std::string update_dir;

    // When non-empty, HTTP connections arriving from this IP are trusted to carry
    // the real client IP in CF-Connecting-IP (Cloudflare) or X-Forwarded-For.
    // Set to "127.0.0.1" when running cloudflared on the same host.
    // Only connections whose remote_addr exactly matches this value are trusted,
    // preventing header injection by direct (non-proxied) connections.
    std::string trusted_proxy;

    // IPs of the server itself (enumerated at startup) and dashboard clients
    // (added on each authenticated request). Used to classify entity flows as
    // monitoring overhead vs. regular traffic in /api/summary.
    // Null = overhead classification disabled (all flows treated as regular).
    std::shared_ptr<MonitoringIpSet> server_ips;
    std::shared_ptr<MonitoringIpSet> dashboard_ips;
};

// Thin httplib::Server subclass that makes process_request() publicly accessible.
// The unified ALPN accept loop calls process_request() directly on pre-accepted
// SSL connections — httplib's own listen() / TLS accept path is never used.
class NtmHttpServer : public httplib::Server
{
public:
    // Lift the protected member to public scope.
    using httplib::Server::process_request;
};

// Register all HTTP route handlers on svr (synchronous; returns immediately).
// The unified ALPN accept loop in server_core feeds connections via
// NtmHttpServer::process_request() — svr.listen() is never called.
void registerWebHandlers(NtmHttpServer   &svr,
                         TrafficStats    &stats,
                         const WebConfig &config);

// Demo server thread (App Store review, port kDemoPort).
// Serves mock /api/summary data; no auth required; browsers rejected by User-Agent.
// Enabled/disabled at runtime via POST /api/admin/demo on the main web server.
// Call svr.stop() from another thread to unblock.
void demoServerThread(httplib::SSLServer &svr);

} // namespace ntm
