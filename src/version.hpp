#pragma once

// ntm-server module version — independent of ntm-client and iOS app versions.
// See CLAUDE.md § Versioning for per-module rules and protocol lockstep requirements.
// Wire protocol spoken: kWireProtoVersion (src/proto_client_server.hpp)
// API protocol spoken:  kApiVersion       (src/proto_client_server.hpp)
inline constexpr char kServerVersion[] = "1.15.3";
