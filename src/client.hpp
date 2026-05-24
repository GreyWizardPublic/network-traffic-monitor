#pragma once

// client.hpp — Public API for the ntm-client module.
//
// Includes client_types.hpp (TransportMode, ClientConfig) and
// client_config_parse.hpp (parseConfigLine, loadClientConfig — inline).
// Callers only need to include this header.

#include "client_config_parse.hpp"   // TransportMode, ClientConfig, loadClientConfig
#include <string>

namespace ntm
{

// Run client. daemonMode is CLI-only; all other settings come from config.
// argv is passed through to startAutoUpdater for exec-self restart on Linux.
int runClient(bool daemonMode, const ClientConfig &config, char **argv);

} // namespace ntm
