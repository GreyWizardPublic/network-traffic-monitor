#pragma once

// client_types.hpp — Plain data types for the ntm-client configuration.
//
// Intentionally dependency-light: only proto_client_server.hpp (for kDefaultPort)
// and standard headers.  This lets client_config_parse.hpp include this header
// without pulling in OpenSSL or platform headers.

#include "proto_client_server.hpp"
#include <cstdint>
#include <cstddef>
#include <string>

namespace ntm
{

// Transport layer used to carry the ntm-wire session.
//   TcpTls   — raw TCP + TLS with ALPN "ntm-wire" (default; direct servers).
//   WebSocket — HTTP/1.1 WebSocket upgrade over TLS (Cloudflare-compatible).
enum class TransportMode { TcpTls, WebSocket };

// All client options in one place.
struct ClientConfig
{
    std::string server{"127.0.0.1"};
    std::uint16_t port{kDefaultPort};
    std::string identityPath;
    std::string tlsCaPath;
    std::string tlsServerCertPath;
    std::size_t sendBufferBytes{0};  // 0 = use default
    bool verbose{false};
    // External IP check: used to group clients behind the same NAT as one LAN.
    // Only queried when at least one LAN interface is present.
    std::string externalIpUrl{"http://checkip.amazonaws.com/"};
    unsigned externalIpTimeoutMs{5000};
    unsigned reconnectMaxAttempts{10};
    unsigned reconnectIntervalSec{60};
    // Auto-update: check for new binary via server HTTPS API once per day.
    bool auto_update{false};            // default off; opt-in via config
    // Deprecated since server v1.15.0 (ALPN port unification): the server now uses
    // a single port (port=) for both data-ingestion and the HTTPS dashboard API.
    // The field is still parsed so existing config files don't error, but it is
    // ignored — the auto-updater connects to config.port instead.
    std::uint16_t web_port{8443};       // deprecated; ignored since server v1.15.0

    // Flow aggregation: accumulate bytes per (iface,src,dst) tuple and flush
    // on an adaptive timer rather than sending one D-line per captured packet.
    std::uint32_t aggTargetLinesPerSec{500};  // max D-lines/sec output (0 = no limit)
    std::uint32_t aggMinIntervalMs{100};      // minimum flush interval (ms)
    std::uint32_t aggMaxIntervalMs{5000};     // maximum flush interval (ms)
    std::uint32_t aggMaxFlows{10000};         // flow-table cap; forced flush when reached

    // zlib stream compression on the data phase (auth v3 + capability exchange).
    // Supported on Linux (system zlib) and Windows (vendored miniz, src/third_party/miniz/).
    // Set to false via config key 'compress=false' or CLI flag '--no-compress'.
    bool useCompression{true};

    // Transport mechanism for the ntm-wire session.
    // TcpTls (default): raw TCP + TLS, direct connection to ntm-server.
    // WebSocket: HTTP/1.1 WebSocket upgrade over TLS, traverses Cloudflare.
    // Config key: transport=tcp|websocket   CLI flag: --transport tcp|websocket
    TransportMode transport{TransportMode::TcpTls};

    // File-based logging (wire-proto v3 remote log management).
    // log_dir: directory for date-named log files; empty = use platform default.
    // log_level: initial verbosity: "Info" (default), "Warn", or "Err".
    //   Overridden at runtime via C set_loglevel from the admin dashboard.
    // Config keys: log_dir=<path>  log_level=Info|Warn|Err
    std::string log_dir;
    std::string log_level{"Info"};
};

} // namespace ntm
