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
};

// Load from one config file (key=value, # comment). Returns defaults for missing keys. Returns false if file missing.
bool loadClientConfig(const std::string &configPath, ClientConfig &out);

// Run client with explicit values (typically merged from config + CLI).
int runClient(const std::string &serverHost,
              std::uint16_t serverPort,
              bool daemonMode,
              const std::string &identityPath = {},
              const std::string &tlsCaPath = {},
              const std::string &tlsServerCertPath = {},
              std::size_t sendBufferBytes = 0,
              bool verbose = false);

} // namespace ntm

