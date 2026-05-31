#pragma once
// web_auth.hpp — pure-logic authentication and request-parsing helpers.
//
// All functions here operate on raw strings and have no dependency on httplib,
// OpenSSL, or any other external library. This makes them directly unit-testable
// (see tests/test_web_auth.cpp) and lets web_dashboard.cpp call them via thin
// httplib::Request wrappers without duplicating the logic.
//
// The canonical example of this pattern is parseDataLine() in
// proto_client_server.hpp.

#include <cstdint>
#include <string>

namespace ntm
{

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

// Extract a named cookie value from a raw Cookie header string.
//   cookieHeader : value of the "Cookie" request header (e.g. "a=1; b=2; c=3")
//   name         : cookie name to look up
// Returns the cookie value, or an empty string if not found.
// The implementation is intentionally simple — it is not a full RFC 6265 parser,
// but it is sufficient for our own server-set cookies whose names never contain
// characters that require quoting or escaping.
inline std::string cookieFromHeader(const std::string &cookieHeader,
                                    const std::string &name)
{
    const std::string prefix = name + "=";
    std::size_t pos = 0;
    while (pos < cookieHeader.size())
    {
        // Skip whitespace after ';'
        while (pos < cookieHeader.size() && cookieHeader[pos] == ' ') ++pos;
        // Check if this token starts exactly with `name=`
        if (cookieHeader.compare(pos, prefix.size(), prefix) == 0)
        {
            std::size_t start = pos + prefix.size();
            std::size_t end   = cookieHeader.find(';', start);
            return cookieHeader.substr(start,
                end == std::string::npos ? std::string::npos : end - start);
        }
        // Advance past this cookie to the next ';'
        pos = cookieHeader.find(';', pos);
        if (pos == std::string::npos) break;
        ++pos;
    }
    return {};
}

// ---------------------------------------------------------------------------
// Session token extraction
// ---------------------------------------------------------------------------

// Extract a session token from raw Authorization and Cookie header strings.
// Priority: Authorization: Bearer <token>  >  ntm_session cookie.
// Returns the token, or an empty string if neither source provides one.
inline std::string sessionFromHeaders(const std::string &authHeader,
                                      const std::string &cookieHeader)
{
    if (authHeader.size() > 7 && authHeader.substr(0, 7) == "Bearer ")
        return authHeader.substr(7);
    return cookieFromHeader(cookieHeader, "ntm_session");
}

// ---------------------------------------------------------------------------
// Client-IP resolution
// ---------------------------------------------------------------------------

// Determine the effective client IP given Cloudflare/reverse-proxy configuration.
//   remoteAddr    : raw TCP remote address (req.remote_addr)
//   trustedProxy  : value of WebConfig::trusted_proxy (empty = direct connection)
//   cfConnectingIP: value of the CF-Connecting-IP request header
//   xForwardedFor : value of the X-Forwarded-For request header
//
// If trustedProxy is non-empty and remoteAddr matches it exactly, the function
// trusts the proxy headers and returns:
//   1. CF-Connecting-IP (if non-empty)
//   2. the first token of X-Forwarded-For (if non-empty)
//   3. remoteAddr as a fallback
// Otherwise remoteAddr is returned directly.
inline std::string effectiveClientIPFromHeaders(const std::string &remoteAddr,
                                                const std::string &trustedProxy,
                                                const std::string &cfConnectingIP,
                                                const std::string &xForwardedFor)
{
    if (trustedProxy.empty() || remoteAddr != trustedProxy)
        return remoteAddr;
    if (!cfConnectingIP.empty()) return cfConnectingIP;
    if (!xForwardedFor.empty())
    {
        auto comma = xForwardedFor.find(',');
        return comma == std::string::npos
                   ? xForwardedFor
                   : xForwardedFor.substr(0, comma);
    }
    return remoteAddr;
}

// ---------------------------------------------------------------------------
// Path classification
// ---------------------------------------------------------------------------

// Returns true if the request path is an authentication or public endpoint that
// may be accessed without a valid WebAuthn session.
// Keep in sync with the isAuthPath check in registerWebHandlers's pre-routing handler.
inline bool isAuthExemptPath(const std::string &path)
{
    if (path == "/login")                                         return true;
    if (path.size() >= 6  && path.substr(0, 6)  == "/auth/")    return true;
    if (path == "/.well-known/apple-app-site-association")       return true;
    if (path == "/api/demo/begin")                               return true;
    // Session-info endpoint: readable without auth so the login page can check siwa_enabled.
    if (path == "/api/session")                                  return true;
    // Update endpoints authenticate via a pubkey query parameter, not a session.
    if (path == "/api/update/check")                             return true;
    if (path == "/api/update/download")                          return true;
    if (path == "/api/update/download_sig")                      return true;
    // Upgrade/push endpoints authenticate via ML-DSA-65 auth proof, not a session.
    if (path == "/admin/upgrade/nonce")                          return true;
    if (path == "/admin/upgrade/push")                           return true;
    if (path == "/admin/client/nonce")                           return true;
    if (path == "/admin/client/push")                            return true;
    return false;
}

// Returns true if the path is under /api/admin/ and therefore requires
// the short-lived ntm_admin proof cookie (in addition to the passkey session).
inline bool isAdminApiPath(const std::string &path)
{
    return path.size() >= 11 && path.substr(0, 11) == "/api/admin/";
}

// ---------------------------------------------------------------------------
// Token prefix guards
// ---------------------------------------------------------------------------

// Returns true if token begins with the "demo_" prefix used for demo tokens.
// A true result does NOT mean the token is valid — the caller must still check
// the in-memory token store.  A false result is a fast early-out.
inline bool hasDemoTokenPrefix(const std::string &token)
{
    return token.size() >= 5 && token.substr(0, 5) == "demo_";
}

// ---------------------------------------------------------------------------
// trusted_proxy validation
// ---------------------------------------------------------------------------

// Returns true if the string is a well-known "catch-all" address that would
// cause the server to unconditionally trust spoofed proxy headers.
// Refused addresses: 0.0.0.0, ::, and the unspecified-address strings.
// A non-empty, non-catch-all address is assumed to be a specific proxy IP
// (validated operationally by the operator).
inline bool isTrustedProxyCatchAll(const std::string &addr)
{
    return addr == "0.0.0.0" || addr == "::" || addr == "0:0:0:0:0:0:0:0";
}

} // namespace ntm
