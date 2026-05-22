#pragma once

// ntm-client (Linux/Windows) module version — independent of ntm-server version.
// See CLAUDE.md § Versioning for per-module rules and protocol lockstep requirements.
// Wire protocol spoken: kWireProtoVersion (src/proto_client_server.hpp)
inline constexpr char kClientVersion[] = "1.8.1";
