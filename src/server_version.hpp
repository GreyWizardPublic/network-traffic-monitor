#pragma once

// ntm-server module version — independent of ntm-client and iOS app versions.
// See docs/agent-framework.md §5 for versioning rules; docs/project-rules.md §3 for the module list.
// Wire protocol spoken: kWireProtoVersion (src/proto_client_server.hpp)
// API protocol spoken:  kApiVersion       (src/proto_client_server.hpp)
inline constexpr char kServerVersion[] = "1.25.0.0";
