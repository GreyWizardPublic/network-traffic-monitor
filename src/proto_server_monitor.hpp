#pragma once

#include <cstdint>
#include <string>

// Server↔Monitor shared protocol constructs (query + summary response).

namespace ntm
{

// Default TCP port for server monitoring endpoint.
inline constexpr std::uint16_t kDefaultMonitorPort = static_cast<std::uint16_t>(5556);

// Monitor query commands.
inline constexpr char kMonitorCmdIfaceSummary[] = "IFACE_SUMMARY";

// Monitor response tokens/lines.
inline constexpr char kMonitorTokWindowStart[] = "WINDOW_START";
inline constexpr char kMonitorTokIface[] = "IFACE";
inline constexpr char kMonitorTokEntity[] = "ENTITY";
inline constexpr char kMonitorTokEnd[] = "END";
inline constexpr char kMonitorTokTruncated[] = "TRUNCATED";

} // namespace ntm

