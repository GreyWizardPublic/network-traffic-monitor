#pragma once

#include "proto_client_server.hpp"
#include <cstdint>
#include <string>

namespace ntm
{

// All client options in one place. Used when loading the single config file.
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
    std::uint16_t web_port{8443};       // server's HTTPS API port (matches server web_port)

    // Flow aggregation: accumulate bytes per (iface,src,dst) tuple and flush
    // on an adaptive timer rather than sending one D-line per captured packet.
    std::uint32_t aggTargetLinesPerSec{500};  // max D-lines/sec output (0 = no limit)
    std::uint32_t aggMinIntervalMs{100};      // minimum flush interval (ms)
    std::uint32_t aggMaxIntervalMs{5000};     // maximum flush interval (ms)
    std::uint32_t aggMaxFlows{10000};         // flow-table cap; forced flush when reached

    // zlib stream compression on the data phase (auth v3 + capability exchange).
    // Linux client only; Windows client always sends kCapNone regardless of this flag.
    // Set to false via config key 'compress=false' or CLI flag '--no-compress'.
    bool useCompression{true};
};

// Load from one config file (key=value, # comment). Returns defaults for missing keys. Returns false if file missing.
bool loadClientConfig(const std::string &configPath, ClientConfig &out);

// Run client. daemonMode is CLI-only; all other settings come from config.
// argv is passed through to startAutoUpdater for exec-self restart on Linux.
int runClient(bool daemonMode, const ClientConfig &config, char **argv);

} // namespace ntm

