#pragma once

// ntm-client (Linux/Windows) module version — independent of ntm-server version.
// See CLAUDE.md § Versioning for per-module rules and protocol lockstep requirements.
// Wire protocol spoken: kWireProtoVersion (src/proto_client_server.hpp)
inline constexpr char kClientVersion[] = "1.11.0";

// Compile-time platform identifier sent in H-lines and used for update manifest lookup.
#ifdef _WIN32
inline constexpr char kClientPlatform[] = "windows-amd64";
#else
inline constexpr char kClientPlatform[] = "linux-amd64";
#endif
