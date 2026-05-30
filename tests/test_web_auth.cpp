// tests/test_web_auth.cpp — unit tests for the pure-logic auth helpers in web_auth.hpp.
//
// These functions were previously duplicated inline inside static lambdas in
// web_dashboard.cpp and therefore untestable. They are now in src/web_auth.hpp
// as inline functions with no external dependencies (no httplib, no OpenSSL).
//
// Run via:  ./build-linux/ntm-tests

#include "ntm_test.hpp"
#include "../src/web_auth.hpp"

// ============================================================================
// cookieFromHeader
// ============================================================================

TEST_CASE("cookieFromHeader: single cookie — exact match")
{
    REQUIRE_EQ(ntm::cookieFromHeader("ntm_session=abc123", "ntm_session"),
               std::string{"abc123"});
}

TEST_CASE("cookieFromHeader: first of several cookies")
{
    REQUIRE_EQ(ntm::cookieFromHeader("ntm_session=tok; other=val; third=x", "ntm_session"),
               std::string{"tok"});
}

TEST_CASE("cookieFromHeader: middle cookie")
{
    REQUIRE_EQ(ntm::cookieFromHeader("a=1; ntm_session=mid; b=2", "ntm_session"),
               std::string{"mid"});
}

TEST_CASE("cookieFromHeader: last cookie (no trailing semicolon)")
{
    REQUIRE_EQ(ntm::cookieFromHeader("a=1; b=2; ntm_admin=last", "ntm_admin"),
               std::string{"last"});
}

TEST_CASE("cookieFromHeader: cookie not present — empty string")
{
    REQUIRE_EQ(ntm::cookieFromHeader("a=1; b=2", "ntm_session"), std::string{});
}

TEST_CASE("cookieFromHeader: empty cookie header — empty string")
{
    REQUIRE_EQ(ntm::cookieFromHeader("", "ntm_session"), std::string{});
}

TEST_CASE("cookieFromHeader: does not match prefix of longer name")
{
    // "ntm_session" must not match "ntm_session_extra=bad"
    REQUIRE_EQ(ntm::cookieFromHeader("ntm_session_extra=bad", "ntm_session"),
               std::string{});
}

TEST_CASE("cookieFromHeader: value may be empty")
{
    REQUIRE_EQ(ntm::cookieFromHeader("ntm_session=; other=x", "ntm_session"),
               std::string{});
}

TEST_CASE("cookieFromHeader: value contains equals sign")
{
    // Base64-style values contain '='; must not be split on them.
    REQUIRE_EQ(ntm::cookieFromHeader("ntm_session=abc==def; x=1", "ntm_session"),
               std::string{"abc==def"});
}

// C-1 regression tests — cookie-name prefix confusion (CWE-1023)
TEST_CASE("cookieFromHeader: does not match suffix-of-longer-name (C-1 regression)")
{
    REQUIRE_EQ(ntm::cookieFromHeader("evil_ntm_session=attacker; ntm_session=good",
                                     "ntm_session"),
               std::string{"good"});
}

TEST_CASE("cookieFromHeader: hostile prefix only returns empty (C-1 regression)")
{
    REQUIRE_EQ(ntm::cookieFromHeader("evil_ntm_admin=attacker", "ntm_admin"),
               std::string{});
}

TEST_CASE("cookieFromHeader: hostile name surrounds real cookie (C-1 regression)")
{
    REQUIRE_EQ(ntm::cookieFromHeader("a=1; xntm_session=bad; ntm_session=real; b=2",
                                     "ntm_session"),
               std::string{"real"});
}

// ============================================================================
// sessionFromHeaders — Authorization bearer takes priority over cookie
// ============================================================================

TEST_CASE("sessionFromHeaders: Bearer token in Authorization header")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("Bearer mytoken123", "ntm_session=ignored"),
               std::string{"mytoken123"});
}

TEST_CASE("sessionFromHeaders: Bearer token is exact after prefix")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("Bearer tok with spaces", ""),
               std::string{"tok with spaces"});
}

TEST_CASE("sessionFromHeaders: no Authorization — falls back to ntm_session cookie")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("", "ntm_session=cookietoken"),
               std::string{"cookietoken"});
}

TEST_CASE("sessionFromHeaders: Basic auth header — not treated as Bearer")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("Basic dXNlcjpwYXNz", "ntm_session=ck"),
               std::string{"ck"});
}

TEST_CASE("sessionFromHeaders: both empty — empty result")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("", ""), std::string{});
}

TEST_CASE("sessionFromHeaders: Authorization too short to be Bearer — uses cookie")
{
    // "Bearer" without a space and token — size <= 7, so not a valid bearer
    REQUIRE_EQ(ntm::sessionFromHeaders("Bearer", "ntm_session=ck"),
               std::string{"ck"});
}

TEST_CASE("sessionFromHeaders: cookie header has ntm_session among others")
{
    REQUIRE_EQ(ntm::sessionFromHeaders("",
               "lang=en; ntm_session=sess99; theme=dark"),
               std::string{"sess99"});
}

// ============================================================================
// effectiveClientIPFromHeaders
// ============================================================================

TEST_CASE("effectiveClientIPFromHeaders: no trusted proxy — returns remote addr")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("1.2.3.4", "", "", ""),
               std::string{"1.2.3.4"});
}

TEST_CASE("effectiveClientIPFromHeaders: remote is not the trusted proxy — returns remote")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("5.5.5.5", "1.1.1.1", "9.9.9.9", ""),
               std::string{"5.5.5.5"});
}

TEST_CASE("effectiveClientIPFromHeaders: remote is proxy — CF-Connecting-IP wins")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("1.1.1.1", "1.1.1.1",
               "203.0.113.5", "10.0.0.1"),
               std::string{"203.0.113.5"});
}

TEST_CASE("effectiveClientIPFromHeaders: remote is proxy — X-Forwarded-For fallback")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("1.1.1.1", "1.1.1.1",
               "", "198.51.100.7"),
               std::string{"198.51.100.7"});
}

TEST_CASE("effectiveClientIPFromHeaders: X-Forwarded-For with multiple IPs — first wins")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("1.1.1.1", "1.1.1.1",
               "", "203.0.113.1, 10.0.0.2, 172.16.0.1"),
               std::string{"203.0.113.1"});
}

TEST_CASE("effectiveClientIPFromHeaders: remote is proxy, no proxy headers — fallback to remote")
{
    REQUIRE_EQ(ntm::effectiveClientIPFromHeaders("1.1.1.1", "1.1.1.1", "", ""),
               std::string{"1.1.1.1"});
}

// ============================================================================
// isAuthExemptPath — paths accessible without a WebAuthn session
// ============================================================================

TEST_CASE("isAuthExemptPath: /login is exempt")
{
    REQUIRE(ntm::isAuthExemptPath("/login"));
}

TEST_CASE("isAuthExemptPath: /auth/ prefix is exempt")
{
    REQUIRE(ntm::isAuthExemptPath("/auth/login/begin"));
    REQUIRE(ntm::isAuthExemptPath("/auth/login/complete"));
    REQUIRE(ntm::isAuthExemptPath("/auth/register/begin"));
    REQUIRE(ntm::isAuthExemptPath("/auth/register/complete"));
}

TEST_CASE("isAuthExemptPath: apple-app-site-association is exempt")
{
    REQUIRE(ntm::isAuthExemptPath("/.well-known/apple-app-site-association"));
}

TEST_CASE("isAuthExemptPath: /api/demo/begin is exempt")
{
    REQUIRE(ntm::isAuthExemptPath("/api/demo/begin"));
}

TEST_CASE("isAuthExemptPath: update endpoints are exempt")
{
    REQUIRE(ntm::isAuthExemptPath("/api/update/check"));
    REQUIRE(ntm::isAuthExemptPath("/api/update/download"));
    REQUIRE(ntm::isAuthExemptPath("/api/update/download_sig"));
}

TEST_CASE("isAuthExemptPath: upgrade and client-push admin endpoints are exempt")
{
    // These endpoints use ML-DSA-65 auth proof internally — not WebAuthn sessions.
    REQUIRE(ntm::isAuthExemptPath("/admin/upgrade/nonce"));
    REQUIRE(ntm::isAuthExemptPath("/admin/upgrade/push"));
    REQUIRE(ntm::isAuthExemptPath("/admin/client/nonce"));
    REQUIRE(ntm::isAuthExemptPath("/admin/client/push"));
}

TEST_CASE("isAuthExemptPath: / (dashboard root) requires session")
{
    REQUIRE(!ntm::isAuthExemptPath("/"));
}

TEST_CASE("isAuthExemptPath: /api/summary requires session")
{
    REQUIRE(!ntm::isAuthExemptPath("/api/summary"));
}

TEST_CASE("isAuthExemptPath: /api/admin/auth requires session")
{
    // /api/admin/ paths need the WebAuthn session (plus admin-proof cookie).
    REQUIRE(!ntm::isAuthExemptPath("/api/admin/auth"));
}

TEST_CASE("isAuthExemptPath: /admin requires session")
{
    REQUIRE(!ntm::isAuthExemptPath("/admin"));
}

TEST_CASE("isAuthExemptPath: /auth without trailing slash is NOT exempt")
{
    // Only the /auth/ prefix (with slash) is exempt — /auth alone must not slip through.
    REQUIRE(!ntm::isAuthExemptPath("/auth"));
}

// ============================================================================
// isAdminApiPath — requires admin-proof cookie on top of WebAuthn session
// ============================================================================

TEST_CASE("isAdminApiPath: /api/admin/auth matches")
{
    REQUIRE(ntm::isAdminApiPath("/api/admin/auth"));
}

TEST_CASE("isAdminApiPath: /api/admin/demo matches")
{
    REQUIRE(ntm::isAdminApiPath("/api/admin/demo"));
}

TEST_CASE("isAdminApiPath: /api/admin/purge matches")
{
    REQUIRE(ntm::isAdminApiPath("/api/admin/purge"));
}

TEST_CASE("isAdminApiPath: /api/summary does not match")
{
    REQUIRE(!ntm::isAdminApiPath("/api/summary"));
}

TEST_CASE("isAdminApiPath: /admin does not match")
{
    REQUIRE(!ntm::isAdminApiPath("/admin"));
}

TEST_CASE("isAdminApiPath: /api/admin prefix without trailing content is boundary")
{
    // "/api/admin/" itself (exactly 11 chars) should match.
    REQUIRE(ntm::isAdminApiPath("/api/admin/"));
}

// ============================================================================
// hasDemoTokenPrefix
// ============================================================================

TEST_CASE("hasDemoTokenPrefix: valid prefix accepted")
{
    REQUIRE(ntm::hasDemoTokenPrefix("demo_aabbccdd"));
}

TEST_CASE("hasDemoTokenPrefix: missing prefix rejected")
{
    REQUIRE(!ntm::hasDemoTokenPrefix("aabbccdd"));
}

TEST_CASE("hasDemoTokenPrefix: empty string rejected")
{
    REQUIRE(!ntm::hasDemoTokenPrefix(""));
}

TEST_CASE("hasDemoTokenPrefix: 'demo' without underscore rejected")
{
    REQUIRE(!ntm::hasDemoTokenPrefix("demoXaabbcc"));
}

TEST_CASE("hasDemoTokenPrefix: exactly 'demo_' (no body) accepted")
{
    // Prefix guard only; store lookup will reject tokens with no body.
    REQUIRE(ntm::hasDemoTokenPrefix("demo_"));
}

// ============================================================================
// hasAdminProofPrefix
// ============================================================================

TEST_CASE("hasAdminProofPrefix: valid prefix accepted")
{
    REQUIRE(ntm::hasAdminProofPrefix("ntm_ap_aabbcc"));
}

TEST_CASE("hasAdminProofPrefix: missing prefix rejected")
{
    REQUIRE(!ntm::hasAdminProofPrefix("aabbcc"));
}

TEST_CASE("hasAdminProofPrefix: empty string rejected")
{
    REQUIRE(!ntm::hasAdminProofPrefix(""));
}

TEST_CASE("hasAdminProofPrefix: 'ntm_ap' without underscore rejected")
{
    REQUIRE(!ntm::hasAdminProofPrefix("ntm_apXaabb"));
}

TEST_CASE("hasAdminProofPrefix: exactly 'ntm_ap_' (no body) accepted")
{
    REQUIRE(ntm::hasAdminProofPrefix("ntm_ap_"));
}

TEST_CASE("hasAdminProofPrefix: demo token does not satisfy admin prefix")
{
    REQUIRE(!ntm::hasAdminProofPrefix("demo_aabb"));
}

// ============================================================================
// isTrustedProxyCatchAll — L-5 regression
// ============================================================================

TEST_CASE("isTrustedProxyCatchAll: 0.0.0.0 is a catch-all (L-5)")
{
    REQUIRE(ntm::isTrustedProxyCatchAll("0.0.0.0"));
}

TEST_CASE("isTrustedProxyCatchAll: :: is a catch-all (L-5)")
{
    REQUIRE(ntm::isTrustedProxyCatchAll("::"));
}

TEST_CASE("isTrustedProxyCatchAll: specific proxy IP is not a catch-all (L-5)")
{
    REQUIRE(!ntm::isTrustedProxyCatchAll("127.0.0.1"));
    REQUIRE(!ntm::isTrustedProxyCatchAll("10.0.0.1"));
    REQUIRE(!ntm::isTrustedProxyCatchAll("192.168.1.1"));
}

TEST_CASE("isTrustedProxyCatchAll: empty string is not a catch-all (L-5)")
{
    REQUIRE(!ntm::isTrustedProxyCatchAll(""));
}
