#pragma once

// updater.hpp — background auto-update thread for ntm-client.
// Checks the server's HTTPS API once per day; downloads and applies new binaries.
// Linux:   atomic rename (same inode slot); optionally exec-self for immediate hot-reload.
// Windows: rename-old trick while running; exits so Task Scheduler restarts with new binary.

#include "client.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace ntm
{

// How an update cycle was initiated (periodic timer vs. wire-4 server push).
enum class UpdateTrigger { Periodic, ServerPush };

// Per-stage callbacks for doOneCheckCycle().  All callbacks are invoked on the
// calling thread.  Set unused callbacks to nullptr — they are checked before use.
struct UpdateCallbacks
{
    // Called once per stage transition (stage names match the L upd wire spec).
    std::function<void(std::string_view stage)>                    onStage;
    // Called on any error; stage_name identifies where it occurred.
    std::function<void(std::string_view stage, std::string_view msg)> onError;
    // Called when the check found no update or update is already in progress.
    std::function<void(std::string_view reason)>                   onNoop;
    // Called just before applying the update (exec/restart).
    // On success this function never returns (process replaced or exited).
    std::function<void(std::string_view new_version)>              onDone;
};

// Run one complete check/download/verify/apply cycle.
// Returns when: no update available (noop), an error occurred (error), or
// on Linux after a failed execv (exec error).  On success the process
// is replaced (Linux execv) or exits (Windows ExitProcess) — never returns.
// Thread-safe: serialised internally by g_updateInProgress atomic.
void doOneCheckCycle(const ClientConfig &config,
                     UpdateTrigger trigger,
                     const UpdateCallbacks &cb);

// Start the background update thread.
// argv is saved for exec-self restart on Linux; pass the argv received by main().
// Does nothing (returns immediately) if config.auto_update is false.
void startAutoUpdater(const ClientConfig &config, char **argv);

// Signal the update thread to stop and join it.
void stopAutoUpdater();

} // namespace ntm
