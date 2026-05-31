#pragma once

// ntm-client (Linux/Windows) module version — independent of ntm-server version.
// See docs/agent-framework.md §5 for versioning rules; docs/project-rules.md §3 for the module list.
// Wire protocol spoken: kWireProtoVersion (src/proto_client_server.hpp)
inline constexpr char kClientVersion[] = "1.21.1.4";

// Compile-time platform identifier sent in H-lines and used for update manifest lookup.
#ifdef _WIN32
inline constexpr char kClientPlatform[] = "windows-amd64";
#else
inline constexpr char kClientPlatform[] = "linux-amd64";
#endif
