#pragma once

// Backward-compat umbrella include. Prefer including the specific protocol header you need.

#include "proto_client_server.hpp"
#include "proto_server_monitor.hpp"

// Server aggregation: rolling window by day (configurable). Default days if not in config.
namespace ntm
{
inline constexpr unsigned kAggregationWindowDaysDefault = 7;
} // namespace ntm

