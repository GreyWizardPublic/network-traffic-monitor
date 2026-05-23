// NTMClient (iOS) module version — independent of ntm-server version.
// Wire protocol spoken: kWireProtoVersion = 2 (must match kWireProtoVersion in
// src/proto_client_server.hpp; see CLAUDE.md § Versioning for lockstep rules).
let kClientVersion    = "1.2.0"
let kWireProtoVersion = 2

// TLS ALPN identifier for the ntm-wire data-ingestion channel.
// Mirrors kAlpnNtmWire in src/proto_client_server.hpp.
// Servers with ALPN port unification route "ntm-wire" → data handler,
// "http/1.1" → dashboard.  Old servers ignore ALPN; backward-compatible.
let kAlpnNtmWire = "ntm-wire"
