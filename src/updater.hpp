#pragma once

// updater.hpp — background auto-update thread for ntm-client.
// Checks the server's HTTPS API once per day; downloads and applies new binaries.
// Linux:   atomic rename (same inode slot); optionally exec-self for immediate hot-reload.
// Windows: rename-old trick while running; exits so Task Scheduler restarts with new binary.

#include "client.hpp"
#include <cstdint>

namespace ntm
{

// Start the background update thread.
// argv is saved for exec-self restart on Linux; pass the argv received by main().
// Does nothing (returns immediately) if config.auto_update is false.
void startAutoUpdater(const ClientConfig &config, char **argv);

// Signal the update thread to stop and join it.
void stopAutoUpdater();

} // namespace ntm
