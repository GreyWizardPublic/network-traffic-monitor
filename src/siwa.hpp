#pragma once
// siwa.hpp — Sign in with Apple: types, pure-logic helpers, and class declarations.
//
// Pure inline helpers (parseJwt, validateAppleClaims, buildAuthorizeUrl,
// matchAdminIdentity) have no OpenSSL or I/O dependency and are directly
// unit-testable (see tests/test_siwa.cpp). They follow the same pattern as
// web_auth.hpp — canonical logic in the header, thin wrappers in cpp.
//
// I/O and crypto classes (SiwaAdminStore, SiwaValidator) are declared here
// and implemented in siwa.cpp.

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ntm
{

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct SiwaConfig
{
    std::string serviceId;        // Apple Service ID (web) e.g. me.happyhomelives.ntm.web
    std::string iosBundleId;      // iOS bundle ID e.g. me.happyhomelives.NTMDashboard (empty = native disabled)
    std::string redirectUri;      // https://<rp>/auth/apple/callback
    std::string adminFile;        // JSON file persisting {email,sub} pairs (survives restart)
    std::string domainAssocText;  // content for /.well-known/apple-developer-domain-association.txt

    bool enabled() const { return !serviceId.empty() && !redirectUri.empty(); }
};

// ---------------------------------------------------------------------------
// Admin identity
// ---------------------------------------------------------------------------

struct SiwaAdminIdentity
{
    std::string email;  // lowercase; operator-configured bootstrap email
    std::string sub;    // Apple stable user ID; empty until first SIWA login (email-bootstrap phase)
};

// ---------------------------------------------------------------------------
// JWT types
// ---------------------------------------------------------------------------

struct JwtParts
{
    std::string headerB64;    // raw base64url header segment
    std::string payloadB64;   // raw base64url payload segment
    std::string sigB64;       // raw base64url signature segment
    std::string signingInput; // headerB64 + "." + payloadB64 (the RS256 input)
    std::string headerJson;   // decoded header JSON
    std::string payloadJson;  // decoded payload JSON
};

// Public key from Apple JWKS endpoint.
struct SiwaJwksKey
{
    std::string kid;  // key ID, matched against JWT header's "kid"
    std::string n;    // base64url RSA modulus
    std::string e;    // base64url RSA exponent (typically "AQAB")
};

// ---------------------------------------------------------------------------
// Pure inline helpers (no OpenSSL, no I/O)
// ---------------------------------------------------------------------------

// Base64url decode (no padding required). Returns empty vector on bad input.
// Uses an accumulator approach identical to WebAuthnRP::fromBase64url in webauthn.cpp.
inline std::vector<uint8_t> siwaBase64urlDecode(const std::string &s)
{
    // Decode table: handles both standard base64 (+/) and base64url (-_); ignores padding.
    int8_t dec[256];
    for (auto &x : dec) x = -1;
    for (int i = 0; i < 26; ++i) { dec['A'+i] = int8_t(i); dec['a'+i] = int8_t(26+i); }
    for (int i = 0; i < 10; ++i) dec['0'+i] = int8_t(52+i);
    dec['+'] = 62; dec['/'] = 63;
    dec['-'] = 62; dec['_'] = 63;  // base64url aliases

    std::vector<uint8_t> out;
    out.reserve((s.size() * 3 + 3) / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : s)
    {
        int8_t v = dec[c];
        if (v < 0) continue;  // skip padding and unknown chars
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(uint8_t((acc >> bits) & 0xFF)); }
    }
    return out;
}

// Split and decode a 3-segment JWT. Returns empty optional on malformed input.
inline std::optional<JwtParts> parseJwt(const std::string &token)
{
    auto dot1 = token.find('.');
    if (dot1 == std::string::npos) return {};
    auto dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return {};

    JwtParts p;
    p.headerB64    = token.substr(0, dot1);
    p.payloadB64   = token.substr(dot1 + 1, dot2 - dot1 - 1);
    p.sigB64       = token.substr(dot2 + 1);
    p.signingInput = token.substr(0, dot2);

    auto hBytes = siwaBase64urlDecode(p.headerB64);
    auto pBytes = siwaBase64urlDecode(p.payloadB64);
    if (hBytes.empty() || pBytes.empty()) return {};

    p.headerJson  = std::string(hBytes.begin(), hBytes.end());
    p.payloadJson = std::string(pBytes.begin(), pBytes.end());
    return p;
}

// Extract a string value from a flat JSON object (handles \\ and \" escapes).
// Tolerates optional whitespace between the colon and the opening quote so that
// both compact JWTs ("key":"value") and pretty-printed JWKS ("key": "value") work.
// Returns "" if not found.
inline std::string jwtGetStr(const std::string &json, const std::string &key)
{
    const std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    // Skip optional whitespace between ':' and '"'
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                  json[pos] == '\n' || json[pos] == '\r')) ++pos;
    if (pos >= json.size() || json[pos] != '"') return {};
    ++pos; // skip opening quote
    std::string val;
    while (pos < json.size() && json[pos] != '"')
    {
        if (json[pos] == '\\' && pos + 1 < json.size()) ++pos; // skip escape prefix
        val += json[pos++];
    }
    return val;
}

// Extract an integer field from a flat JSON object. Returns 0 if not found.
inline long long jwtGetLong(const std::string &json, const std::string &key)
{
    const std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    while (pos < json.size() && json[pos] == ' ') ++pos;
    if (pos >= json.size()) return 0;
    long long v = 0;
    bool neg = false;
    if (json[pos] == '-') { neg = true; ++pos; }
    while (pos < json.size() && (unsigned char)(json[pos] - '0') <= 9)
        v = v * 10 + (json[pos++] - '0');
    return neg ? -v : v;
}

// Validate Apple id_token claims. Returns "" on success, error string on failure.
// allowedAuds: {serviceId} for web flow, {iosBundleId} for native, or both.
// expectedNonceHash: SHA-256 hex of the stored raw nonce (pass "" to skip nonce check).
inline std::string validateAppleClaims(const std::string &payloadJson,
                                        const std::vector<std::string> &allowedAuds,
                                        const std::string &expectedNonceHash,
                                        long long nowUtcSec)
{
    if (jwtGetStr(payloadJson, "iss") != "https://appleid.apple.com")
        return "iss mismatch";

    const std::string aud = jwtGetStr(payloadJson, "aud");
    bool audOk = false;
    for (const auto &a : allowedAuds) if (a == aud) { audOk = true; break; }
    if (!audOk) return "aud not in allowlist: " + aud;

    const long long exp = jwtGetLong(payloadJson, "exp");
    // Allow up to 30 s of clock skew: reject only if the token has been expired
    // for more than 30 seconds from the server's perspective.  This tolerates a
    // server clock that is up to 30 s ahead of Apple's without spurious failures.
    static constexpr long long kClockSkewSec = 30;
    if (exp == 0 || nowUtcSec > exp + kClockSkewSec) return "token expired";

    if (!expectedNonceHash.empty())
    {
        if (jwtGetStr(payloadJson, "nonce") != expectedNonceHash)
            return "nonce mismatch";
    }
    return {};
}

// Build the authorization redirect URL for the web flow.
// nonceHash must be SHA-256 hex of the raw nonce stored in the pending session.
inline std::string buildAuthorizeUrl(const std::string &serviceId,
                                      const std::string &redirectUri,
                                      const std::string &state,
                                      const std::string &nonceHash)
{
    auto urlEncode = [](const std::string &s) {
        std::string r;
        r.reserve(s.size() * 3);
        for (unsigned char c : s)
        {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                r += (char)c;
            else
            {
                char h[4];
                std::snprintf(h, sizeof(h), "%%%02X", c);
                r += h;
            }
        }
        return r;
    };

    return "https://appleid.apple.com/auth/authorize"
           "?response_type=code%20id_token"
           "&response_mode=form_post"
           "&client_id="    + urlEncode(serviceId)   +
           "&redirect_uri=" + urlEncode(redirectUri)  +
           "&scope=email"
           "&state="        + urlEncode(state)        +
           "&nonce="        + urlEncode(nonceHash);
}

// Case-insensitive ASCII email comparison.
inline bool siwaEmailsEqual(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
            return false;
    return true;
}

// Find admin record matching sub (priority) then unpinned email.
// Returns the index into `ids`, or -1 if no match.
// A sub match means the identity is confirmed; an email-only match means the sub
// should be pinned by the caller (email-bootstrap phase).
// Records with a sub but empty email are sub-only entries (added via siwa_admin_subs
// config key) — they match by sub regardless of the provided email.
inline int matchAdminIdentity(const std::vector<SiwaAdminIdentity> &ids,
                               const std::string &sub,
                               const std::string &email)
{
    // Priority 1: sub match (pinned or sub-only entry)
    for (int i = 0; i < (int)ids.size(); ++i)
        if (!ids[i].sub.empty() && ids[i].sub == sub) return i;
    // Priority 2: email match on unpinned record (bootstrap when real email is provided)
    if (!email.empty())
        for (int i = 0; i < (int)ids.size(); ++i)
            if (ids[i].sub.empty() && siwaEmailsEqual(ids[i].email, email)) return i;
    return -1;
}

// ---------------------------------------------------------------------------
// SiwaAdminStore — thread-safe persistence of {email, sub} admin identities
// ---------------------------------------------------------------------------

// Manages the list of admin Apple identities:
//   • Loaded from `filePath` (JSON) on construction.
//   • Seeded with operator-configured emails (configEmails) and/or subs
//     (configSubs) if those identities are not already present in the file.
//   • configSubs entries are added as sub-only records (empty email) — useful
//     for operators who use "Hide My Email" and know their Apple sub from logs.
//   • Saves back when a sub is pinned on first successful login (email-bootstrap).
class SiwaAdminStore
{
public:
    // filePath: path to the JSON persistence file (may not exist yet).
    // configEmails: comma-separated admin email addresses (siwa_admins config key).
    // configSubs: comma-separated Apple stable user IDs (siwa_admin_subs config key).
    SiwaAdminStore(const std::string &filePath,
                   const std::string &configEmails,
                   const std::string &configSubs = {});

    // Check if this sub/email pair belongs to an admin.
    // If matched by email only (sub not yet pinned), pin the sub and persist.
    // Returns true if admin, false otherwise.
    bool matchAndPin(const std::string &sub, const std::string &email);

    // Return a snapshot of all identities (for logging / admin UI).
    std::vector<SiwaAdminIdentity> list() const;

private:
    mutable std::mutex mtx_;
    std::string filePath_;
    std::vector<SiwaAdminIdentity> identities_;

    void load();
    void save() const;  // call holding mtx_
};

// ---------------------------------------------------------------------------
// SiwaValidator — JWKS cache + pending state management + JWT verification
// ---------------------------------------------------------------------------

class SiwaValidator
{
public:
    explicit SiwaValidator(const SiwaConfig &cfg);

    // Begin a web-flow sign-in: generate state + nonce, store pending entry,
    // return the Apple authorization redirect URL.
    // stateOut receives the state value for the caller to record (e.g. in a
    // short-lived HTTP-only cookie with SameSite=None so it survives the
    // cross-site form_post redirect).  The state IS the session key; look up
    // the nonce by state in verifyCallback.
    std::string beginFlow(std::string &stateOut);

    struct VerifyResult
    {
        bool        ok{false};
        std::string sub;
        std::string email;
        std::string error;
    };

    // Verify a web-flow callback.  Looks up state in the pending map, extracts
    // the nonce, validates the id_token JWT (signature + claims + nonce).
    VerifyResult verifyCallback(const std::string &state,
                                 const std::string &idToken,
                                 const std::vector<std::string> &allowedAuds);

    // Verify a native (iOS) id_token directly; no state/nonce check.
    VerifyResult verifyNative(const std::string &idToken,
                               const std::vector<std::string> &allowedAuds);

    // --- Testing hook ---
    // Inject a pre-parsed JWKS, bypassing the Apple network fetch.
    // Call before verifyCallback / verifyNative in unit tests.
    void setTestJwks(const std::vector<SiwaJwksKey> &keys);

private:
    SiwaConfig cfg_;

    struct PendingState
    {
        std::string nonceRaw;  // raw random bytes (hex); SHA-256 hex of this was sent to Apple
        std::chrono::steady_clock::time_point expiry;
    };

    mutable std::mutex mtx_;
    std::unordered_map<std::string, PendingState> pending_;
    std::vector<SiwaJwksKey> jwksKeys_;
    std::chrono::steady_clock::time_point jwksExpiry_{};
    bool testMode_{false};

    void sweepPending();              // call holding mtx_
    bool ensureJwks();                // refresh JWKS from Apple if stale; returns false on failure
    bool rsaVerifyRS256(const SiwaJwksKey &key,
                         const std::string &signingInput,
                         const std::string &sigB64) const;
    VerifyResult verifyJwt(const std::string &idToken,
                            const std::vector<std::string> &allowedAuds,
                            const std::string &expectedNonceHash);

    static std::string sha256Hex(const std::string &data);
    static std::string randomHex(std::size_t nBytes);
    static std::vector<SiwaJwksKey> parseJwksJson(const std::string &json);
};

} // namespace ntm
