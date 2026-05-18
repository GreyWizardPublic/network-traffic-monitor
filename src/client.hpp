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
};

// Load from one config file (key=value, # comment). Returns defaults for missing keys. Returns false if file missing.
bool loadClientConfig(const std::string &configPath, ClientConfig &out);

// Run client. daemonMode is CLI-only; all other settings come from config.
int runClient(bool daemonMode, const ClientConfig &config);

} // namespace ntm

