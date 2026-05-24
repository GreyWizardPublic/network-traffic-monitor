#pragma once

// client_http_util.hpp — Pure-logic HTTP utility helpers shared between
// client_linux.cpp and client_windows.cpp.
//
// No syscalls, no platform headers — safe to include in any translation unit
// and to test without a network or WSA initialisation.

#include <string>
#include <cstddef>

namespace ntm::http_util
{

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

struct ParsedUrl
{
    std::string host;       // hostname or IP literal
    std::string port;       // decimal port string (e.g. "80")
    std::string path;       // request path, always starts with '/'
    bool        ok{false};  // false if the URL was rejected
};

// Parse a plain "http://…" URL into its components.
// Returns ok=false for anything that isn't a well-formed http:// URL with a
// non-empty host.  https://, ftp://, and empty strings all return ok=false.
inline ParsedUrl parseHttpUrl(const std::string &url)
{
    ParsedUrl result;
    constexpr std::string_view kPrefix = "http://";
    if (url.size() <= kPrefix.size() ||
        url.substr(0, kPrefix.size()) != kPrefix)
        return result;                 // not http://

    std::string rest = url.substr(kPrefix.size());
    if (rest.empty()) return result;

    auto slashPos  = rest.find('/');
    std::string hostPort = (slashPos == std::string::npos) ? rest : rest.substr(0, slashPos);
    result.path    = (slashPos == std::string::npos) ? "/" : rest.substr(slashPos);

    // Split host:port
    auto colonPos = hostPort.rfind(':');
    if (colonPos != std::string::npos)
    {
        result.host = hostPort.substr(0, colonPos);
        result.port = hostPort.substr(colonPos + 1);
    }
    else
    {
        result.host = hostPort;
        result.port = "80";
    }

    if (result.host.empty() || result.port.empty())
        return result;   // ok stays false

    result.ok = true;
    return result;
}

// ---------------------------------------------------------------------------
// HTTP response body extraction
// ---------------------------------------------------------------------------

// Extract the body from a raw HTTP/1.x response string.
// Finds the blank-line separator (\r\n\r\n), strips trailing and leading
// whitespace from the body, and removes a leading length line if present
// (HTTP/1.0 chunked-like responses from some checkip services).
// Returns an empty string if the separator is not found.
inline std::string extractHttpBody(const std::string &response)
{
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return {};

    std::string body = response.substr(pos + 4);

    // Strip trailing whitespace
    while (!body.empty() && (body.back() == '\r' || body.back() == '\n' ||
                              body.back() == ' '  || body.back() == '\t'))
        body.pop_back();

    // Strip leading whitespace
    auto bstart = body.find_first_not_of(" \r\n\t");
    if (bstart != std::string::npos && bstart > 0)
        body = body.substr(bstart);

    // Some HTTP/1.0 servers send a short hex chunk-size line first; if the
    // first "line" is ≤7 chars and followed by a newline, discard it.
    auto nl = body.find('\n');
    if (nl != std::string::npos && nl <= 7)
        body = body.substr(nl + 1);

    // Strip trailing whitespace again (after possible chunk-size removal)
    while (!body.empty() && (body.back() == '\r' || body.back() == '\n' ||
                              body.back() == ' '  || body.back() == '\t'))
        body.pop_back();

    return body;
}

// ---------------------------------------------------------------------------
// HTTP request building
// ---------------------------------------------------------------------------

// Build a minimal HTTP/1.0 GET request string.
inline std::string buildGetRequest(const std::string &path,
                                   const std::string &host)
{
    return "GET " + path + " HTTP/1.0\r\n"
           "Host: " + host + "\r\n"
           "Connection: close\r\n"
           "\r\n";
}

} // namespace ntm::http_util
