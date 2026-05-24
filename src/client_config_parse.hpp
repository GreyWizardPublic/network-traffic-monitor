#pragma once

// client_config_parse.hpp — Pure-logic helpers for parsing the ntm-client
// configuration file (key=value format).
//
// All functions are inline with no OpenSSL or platform dependencies, so they
// can be included directly by the unit-test binary.  client_core.cpp includes
// this header and delegates loadClientConfig / parseConfigLine here.
//
// See docs/wire-protocol.md for the config key reference.

#include "client_types.hpp"    // ClientConfig, TransportMode

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <string>

namespace ntm
{

// Sizing limits (duplicated here so this header compiles without client_core.hpp
// and its transitive OpenSSL dependency).
namespace cfg_detail
{
    inline constexpr std::size_t kMaxLineLen  = 8192;
    inline constexpr std::size_t kMaxValueLen = 2048;
    inline constexpr std::size_t kMinSendBuf  = 4096;
    inline constexpr std::size_t kMaxSendBuf  = 2 * 1024 * 1024;
}

// ---------------------------------------------------------------------------
// parseConfigLine — set one field of `out` from a key/value pair.
// Returns true if key was recognised (even if the value was invalid).
// ---------------------------------------------------------------------------

inline bool parseConfigLine(const std::string &key, const std::string &val,
                            ClientConfig &out)
{
    std::string v = val.size() <= cfg_detail::kMaxValueLen
                        ? val
                        : val.substr(0, cfg_detail::kMaxValueLen);

    if (key == "server")      { out.server = v; return true; }
    if (key == "port")
    {
        try {
            unsigned long p = std::stoul(v);
            if (p != 0 && p <= 65535) out.port = static_cast<std::uint16_t>(p);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "identity")    { out.identityPath = v; return true; }
    if (key == "ca")          { out.tlsCaPath = v; return true; }
    if (key == "server_cert") { out.tlsServerCertPath = v; return true; }
    if (key == "send_buffer_bytes")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n < cfg_detail::kMinSendBuf) n = static_cast<unsigned long>(cfg_detail::kMinSendBuf);
            if (n > cfg_detail::kMaxSendBuf) n = static_cast<unsigned long>(cfg_detail::kMaxSendBuf);
            out.sendBufferBytes = static_cast<std::size_t>(n);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "verbose")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        out.verbose = (lower == "1" || lower == "true" || lower == "yes");
        return true;
    }
    if (key == "external_ip_url")
    {
        if (!v.empty()) out.externalIpUrl = v;
        return true;
    }
    if (key == "external_ip_timeout_ms")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n >= 500 && n <= 30000)
                out.externalIpTimeoutMs = static_cast<unsigned>(n);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "reconnect_attempts")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n >= 1 && n <= 1000) out.reconnectMaxAttempts = static_cast<unsigned>(n);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "reconnect_interval_sec")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n >= 1 && n <= 3600) out.reconnectIntervalSec = static_cast<unsigned>(n);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "auto_update")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        out.auto_update = (lower == "1" || lower == "true" || lower == "yes");
        return true;
    }
    if (key == "web_port")
    {
        // Deprecated since server v1.15.0: the server uses one unified port
        // (port=) for both data-ingestion and the HTTPS dashboard API.
        // Still accepted so existing config files don't error, but ignored.
        std::cerr << "ntm-client: config: 'web_port' is deprecated since server "
                     "v1.15.0 (unified port); the value is ignored. "
                     "Remove it from your config file.\n";
        return true;
    }
    if (key == "agg_target_lines_per_sec")
    {
        try {
            unsigned long n = std::stoul(v);
            out.aggTargetLinesPerSec =
                static_cast<std::uint32_t>(std::min(n, 1000000ul));
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "agg_min_interval_ms")
    {
        try {
            unsigned long n = std::stoul(v);
            out.aggMinIntervalMs =
                static_cast<std::uint32_t>(std::clamp(n, 50ul, 5000ul));
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "agg_max_interval_ms")
    {
        try {
            unsigned long n = std::stoul(v);
            out.aggMaxIntervalMs =
                static_cast<std::uint32_t>(std::clamp(n, 100ul, 60000ul));
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "agg_max_flows")
    {
        try {
            unsigned long n = std::stoul(v);
            out.aggMaxFlows =
                static_cast<std::uint32_t>(std::clamp(n, 100ul, 1000000ul));
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "compress")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        out.useCompression = !(lower == "0" || lower == "false" || lower == "no");
        return true;
    }
    if (key == "transport")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        if (lower == "websocket" || lower == "ws")
            out.transport = TransportMode::WebSocket;
        else
            out.transport = TransportMode::TcpTls;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// loadClientConfig — read and parse a key=value config file.
// Returns false if the file cannot be opened.
// ---------------------------------------------------------------------------

inline bool loadClientConfig(const std::string &configPath, ClientConfig &out)
{
    std::ifstream f(configPath);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.size() > cfg_detail::kMaxLineLen)
            line.resize(cfg_detail::kMaxLineLen);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') continue;
        std::size_t eq = line.find('=', start);
        if (eq == std::string::npos) continue;
        std::string key = line.substr(start, eq - start);
        std::size_t keyEnd = key.find_last_not_of(" \t");
        if (keyEnd != std::string::npos && keyEnd < key.size())
            key.resize(keyEnd + 1);
        std::string val = line.substr(eq + 1);
        std::size_t valStart = val.find_first_not_of(" \t");
        if (valStart != std::string::npos) val = val.substr(valStart);
        parseConfigLine(key, val, out);
    }
    return true;
}

} // namespace ntm
