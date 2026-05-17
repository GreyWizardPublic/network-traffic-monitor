#pragma once

// web_dashboard.hpp — HTTPS dashboard interface.
// Add new web config knobs to WebConfig; add new endpoints in web_dashboard.cpp.
// server_core populates WebConfig from ServerConfig at thread-launch time.

#include "ntm_types.hpp"

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
    std::string   token;              // empty = no bearer-token auth
    unsigned      rate_limit_rpm{30};
    std::size_t   max_entity_lines{50000};
    // Display-time nickname substitution: lowercase 64-hex pubkey → human-readable name.
    // The internal clientId in TrafficStats is always the raw hex; lookup happens only at
    // JSON serialisation so renaming a client never orphans historical data.
    std::unordered_map<std::string, std::string> client_nicknames;
    // Shared registry mapping a client's LAN IP → display name, populated by each
    // connectionThread on authentication and read by buildSummaryJson per request.
    std::shared_ptr<ClientRegistry> registry;
};

// Thread function: registers HTTP routes on svr, then blocks in svr.listen().
// Call svr.stop() from another thread to unblock.
void webServerThread(httplib::SSLServer &svr,
                     TrafficStats       &stats,
                     const WebConfig    &config);

} // namespace ntm
