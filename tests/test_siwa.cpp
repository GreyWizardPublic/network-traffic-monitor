// tests/test_siwa.cpp — Unit tests for Sign in with Apple helpers.
//
// Three layers tested:
//   1. Pure inline helpers: parseJwt, validateAppleClaims, buildAuthorizeUrl,
//      matchAdminIdentity, jwtGetStr, jwtGetLong, siwaEmailsEqual.
//   2. SiwaAdminStore: email seeding, sub-pinning, disk persistence round-trip.
//   3. SiwaValidator: JWT RS256 verification with a locally-generated RSA key
//      injected via setTestJwks — no network calls.

#include "ntm_test.hpp"
#include "../src/siwa.hpp"

#include <ctime>
#include <filesystem>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// ---------------------------------------------------------------------------
// Local utilities (test-only)
// ---------------------------------------------------------------------------

static std::string b64urlEncode(const uint8_t *data, std::size_t len)
{
    static const char *kAlph =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve((len + 2) / 3 * 4);
    for (std::size_t i = 0; i < len; i += 3)
    {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)data[i + 2];
        b64 += kAlph[(v >> 18) & 63];
        b64 += kAlph[(v >> 12) & 63];
        b64 += (i + 1 < len) ? kAlph[(v >> 6) & 63] : '=';
        b64 += (i + 2 < len) ? kAlph[v & 63] : '=';
    }
    for (char &c : b64)
        if (c == '+') c = '-'; else if (c == '/') c = '_';
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return b64;
}

static std::string b64urlEncodeStr(const std::string &s)
{
    return b64urlEncode(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

// Build and sign a JWT with the given EVP_PKEY.
static std::string makeJwt(EVP_PKEY *pkey,
                             const std::string &headerJson,
                             const std::string &payloadJson)
{
    const std::string h = b64urlEncodeStr(headerJson);
    const std::string p = b64urlEncodeStr(payloadJson);
    const std::string input = h + "." + p;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    std::vector<uint8_t> sig;
    if (ctx)
    {
        std::size_t sigLen = 0;
        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestSignUpdate(ctx, input.data(), input.size()) == 1 &&
            EVP_DigestSignFinal(ctx, nullptr, &sigLen) == 1)
        {
            sig.resize(sigLen);
            EVP_DigestSignFinal(ctx, sig.data(), &sigLen);
            sig.resize(sigLen);
        }
        EVP_MD_CTX_free(ctx);
    }
    return input + "." + b64urlEncode(sig.data(), sig.size());
}

// Build a token with canonical Apple claims.
static std::string makeAppleToken(EVP_PKEY *pkey,
                                   const std::string &kid,
                                   const std::string &aud,
                                   long long expOffset,   // seconds relative to now()
                                   const std::string &sub   = "user_sub_1",
                                   const std::string &email = "user@example.com",
                                   const std::string &nonce = "")
{
    const std::string header = "{\"kid\":\"" + kid + "\",\"alg\":\"RS256\"}";
    long long exp = (long long)std::time(nullptr) + expOffset;
    std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                          "\"aud\":\"" + aud + "\","
                          "\"sub\":\"" + sub + "\","
                          "\"email\":\"" + email + "\","
                          "\"exp\":" + std::to_string(exp);
    if (!nonce.empty()) payload += ",\"nonce\":\"" + nonce + "\"";
    payload += "}";
    return makeJwt(pkey, header, payload);
}

// Extract RSA n/e as base64url from a public EVP_PKEY.
static bool rsaParts(EVP_PKEY *pkey, std::string &nOut, std::string &eOut)
{
    BIGNUM *n = nullptr, *e = nullptr;
    bool ok = (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1 &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1);
    if (ok)
    {
        std::vector<uint8_t> nb((std::size_t)BN_num_bytes(n));
        std::vector<uint8_t> eb((std::size_t)BN_num_bytes(e));
        BN_bn2bin(n, nb.data());
        BN_bn2bin(e, eb.data());
        nOut = b64urlEncode(nb.data(), nb.size());
        eOut = b64urlEncode(eb.data(), eb.size());
    }
    BN_free(n); BN_free(e);
    return ok;
}

// One RSA-2048 key shared across all validator tests.
struct TestKey
{
    EVP_PKEY *pkey{nullptr};
    std::string nB64, eB64;
    bool ready{false};

    TestKey()
    {
        // EVP_RSA_gen is the OpenSSL 3.x simple RSA key generation function.
        pkey = EVP_RSA_gen(2048);
        if (pkey) ready = rsaParts(pkey, nB64, eB64);
    }
    ~TestKey() { EVP_PKEY_free(pkey); }

    ntm::SiwaJwksKey key(const std::string &kid = "tid") const
    {
        return {kid, nB64, eB64};
    }
};

static TestKey gKey;

// Default test SiwaConfig.
static ntm::SiwaConfig testCfg()
{
    ntm::SiwaConfig c;
    c.serviceId   = "me.test.web";
    c.iosBundleId = "me.test.ios";
    c.redirectUri = "https://test.example.com/auth/apple/callback";
    return c;
}

// ===========================================================================
// Pure inline helpers
// ===========================================================================

TEST_CASE("siwa: parseJwt: well-formed 3-segment token")
{
    const std::string tok =
        b64urlEncodeStr("{\"alg\":\"RS256\"}") + "." +
        b64urlEncodeStr("{\"sub\":\"u1\"}") + "." +
        b64urlEncodeStr("sig");
    auto p = ntm::parseJwt(tok);
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->headerJson,  std::string{"{\"alg\":\"RS256\"}"});
    REQUIRE_EQ(p->payloadJson, std::string{"{\"sub\":\"u1\"}"});
}

TEST_CASE("siwa: parseJwt: two segments — returns nullopt")
{
    REQUIRE(!ntm::parseJwt("only.two").has_value());
}

TEST_CASE("siwa: parseJwt: no dots — returns nullopt")
{
    REQUIRE(!ntm::parseJwt("nodots").has_value());
}

TEST_CASE("siwa: parseJwt: empty string — returns nullopt")
{
    REQUIRE(!ntm::parseJwt("").has_value());
}

TEST_CASE("siwa: parseJwt: signing_input is header.payload")
{
    const std::string h = b64urlEncodeStr("{\"alg\":\"RS256\"}");
    const std::string p = b64urlEncodeStr("{\"sub\":\"u1\"}");
    const std::string s = b64urlEncodeStr("sig");
    auto parts = ntm::parseJwt(h + "." + p + "." + s);
    REQUIRE(parts.has_value());
    REQUIRE_EQ(parts->signingInput, h + "." + p);
}

TEST_CASE("siwa: jwtGetStr: key present")
{
    REQUIRE_EQ(ntm::jwtGetStr("{\"sub\":\"u1\",\"iss\":\"a\"}", "sub"),
               std::string{"u1"});
}

TEST_CASE("siwa: jwtGetStr: key absent — empty string")
{
    REQUIRE_EQ(ntm::jwtGetStr("{\"sub\":\"u1\"}", "iss"), std::string{});
}

TEST_CASE("siwa: jwtGetStr: escaped quote in value")
{
    REQUIRE_EQ(ntm::jwtGetStr("{\"k\":\"a\\\"b\"}", "k"), std::string{"a\"b"});
}

TEST_CASE("siwa: jwtGetLong: key present")
{
    REQUIRE(ntm::jwtGetLong("{\"exp\":1234567890}", "exp") == 1234567890LL);
}

TEST_CASE("siwa: jwtGetLong: key absent — returns 0")
{
    REQUIRE(ntm::jwtGetLong("{\"exp\":1}", "iat") == 0LL);
}

TEST_CASE("siwa: validateAppleClaims: valid claims pass")
{
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now + 300) + ","
                                "\"nonce\":\"abc123\"}";
    REQUIRE(ntm::validateAppleClaims(payload, {"me.example.web"}, "abc123", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: wrong iss fails")
{
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://evil.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now + 300) + "}";
    REQUIRE(!ntm::validateAppleClaims(payload, {"me.example.web"}, "", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: wrong aud fails")
{
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.evil\","
                                "\"exp\":" + std::to_string(now + 300) + "}";
    REQUIRE(!ntm::validateAppleClaims(payload, {"me.good"}, "", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: expired token fails")
{
    // Token expired 60 s ago — beyond the 30 s clock-skew grace window.
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now - 60) + "}";
    REQUIRE(!ntm::validateAppleClaims(payload, {"me.example.web"}, "", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: token within clock-skew grace window passes")
{
    // Token expired 10 s ago — within the 30 s grace window, should still pass.
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now - 10) + "}";
    REQUIRE(ntm::validateAppleClaims(payload, {"me.example.web"}, "", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: nonce mismatch fails")
{
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now + 300) + ","
                                "\"nonce\":\"wronghash\"}";
    REQUIRE(!ntm::validateAppleClaims(payload, {"me.example.web"}, "expecthash", now).empty());
}

TEST_CASE("siwa: validateAppleClaims: nonce skipped when empty expected hash")
{
    const long long now = (long long)std::time(nullptr);
    const std::string payload = "{\"iss\":\"https://appleid.apple.com\","
                                "\"aud\":\"me.example.web\","
                                "\"exp\":" + std::to_string(now + 300) + "}";
    REQUIRE(ntm::validateAppleClaims(payload, {"me.example.web"}, "", now).empty());
}

TEST_CASE("siwa: buildAuthorizeUrl: contains required fields")
{
    const std::string url = ntm::buildAuthorizeUrl("svc.id",
                                                    "https://example.com/cb",
                                                    "st8", "n0nce");
    REQUIRE(url.find("appleid.apple.com/auth/authorize") != std::string::npos);
    REQUIRE(url.find("svc.id") != std::string::npos);
    REQUIRE(url.find("st8") != std::string::npos);
    REQUIRE(url.find("n0nce") != std::string::npos);
    REQUIRE(url.find("form_post") != std::string::npos);
    REQUIRE(url.find("scope=email") != std::string::npos);
}

TEST_CASE("siwa: buildAuthorizeUrl: special chars percent-encoded")
{
    const std::string url = ntm::buildAuthorizeUrl("sid",
                                                    "https://a.com/cb?x=1",
                                                    "s", "n");
    // '?' and '=' in the redirect URI must be percent-encoded
    REQUIRE(url.find("%3F") != std::string::npos);
}

TEST_CASE("siwa: siwaEmailsEqual: case insensitive")
{
    REQUIRE(ntm::siwaEmailsEqual("User@Example.COM", "user@example.com"));
    REQUIRE(!ntm::siwaEmailsEqual("a@b.com", "c@b.com"));
    REQUIRE(!ntm::siwaEmailsEqual("a@b.com", "a@b.co"));
}

TEST_CASE("siwa: matchAdminIdentity: sub match wins over email")
{
    const std::vector<ntm::SiwaAdminIdentity> ids = {
        {"admin@example.com", "sub1"},
        {"other@example.com", ""},
    };
    // sub1 matches record 0 — should win even though email would match record 1
    REQUIRE(ntm::matchAdminIdentity(ids, "sub1", "other@example.com") == 0);
}

TEST_CASE("siwa: matchAdminIdentity: email bootstrap when sub empty")
{
    const std::vector<ntm::SiwaAdminIdentity> ids = {
        {"admin@example.com", ""},
    };
    REQUIRE(ntm::matchAdminIdentity(ids, "freshSub", "ADMIN@EXAMPLE.COM") == 0);
}

TEST_CASE("siwa: matchAdminIdentity: no match returns -1")
{
    const std::vector<ntm::SiwaAdminIdentity> ids = {
        {"admin@example.com", "sub1"},
    };
    REQUIRE(ntm::matchAdminIdentity(ids, "other", "notadmin@example.com") == -1);
}

TEST_CASE("siwa: matchAdminIdentity: pinned sub blocks email-only bootstrap")
{
    const std::vector<ntm::SiwaAdminIdentity> ids = {
        {"admin@example.com", "correctSub"},
    };
    // Wrong sub, correct email — record has a pinned sub so email-bootstrap should NOT fire.
    REQUIRE(ntm::matchAdminIdentity(ids, "wrongSub", "admin@example.com") == -1);
}

// ===========================================================================
// SiwaAdminStore
// ===========================================================================

TEST_CASE("siwa_store: seed from comma-separated config emails")
{
    const std::string path = "/tmp/ntm_siwastore_seed.json";
    std::filesystem::remove(path);
    ntm::SiwaAdminStore store(path, "Admin@Example.COM, second@example.com");
    auto ids = store.list();
    REQUIRE(ids.size() == 2u);
    REQUIRE_EQ(ids[0].email, std::string{"admin@example.com"});  // lowercased
    REQUIRE(ids[0].sub.empty());
    std::filesystem::remove(path);
}

TEST_CASE("siwa_store: matchAndPin by email pins sub and persists")
{
    const std::string path = "/tmp/ntm_siwastore_pin.json";
    std::filesystem::remove(path);
    {
        ntm::SiwaAdminStore store(path, "admin@example.com");
        REQUIRE(store.matchAndPin("apple_sub_1", "admin@example.com"));
        REQUIRE_EQ(store.list()[0].sub, std::string{"apple_sub_1"});
    }
    // Reload: sub must survive restart.
    {
        ntm::SiwaAdminStore store2(path, "admin@example.com");
        auto ids = store2.list();
        REQUIRE(!ids.empty());
        REQUIRE_EQ(ids[0].sub, std::string{"apple_sub_1"});
    }
    std::filesystem::remove(path);
}

TEST_CASE("siwa_store: no match for unknown sub and email")
{
    const std::string path = "/tmp/ntm_siwastore_nomatch.json";
    std::filesystem::remove(path);
    ntm::SiwaAdminStore store(path, "admin@example.com");
    REQUIRE(!store.matchAndPin("sub999", "notadmin@example.com"));
    std::filesystem::remove(path);
}

TEST_CASE("siwa_store: sub match after pin works with different email")
{
    const std::string path = "/tmp/ntm_siwastore_submatch.json";
    std::filesystem::remove(path);
    ntm::SiwaAdminStore store(path, "admin@example.com");
    REQUIRE(store.matchAndPin("apple_sub_2", "admin@example.com"));
    // Subsequent login with same sub but different email (private-relay changed).
    REQUIRE(store.matchAndPin("apple_sub_2", "relay1234@privaterelay.appleid.com"));
    std::filesystem::remove(path);
}

TEST_CASE("siwa_store: no duplicate email entries on reload")
{
    const std::string path = "/tmp/ntm_siwastore_dedup.json";
    std::filesystem::remove(path);
    {
        ntm::SiwaAdminStore store(path, "admin@example.com");
        store.matchAndPin("sub1", "admin@example.com");
    }
    // Reload with same email in config — should not add a second entry.
    ntm::SiwaAdminStore store2(path, "admin@example.com");
    REQUIRE_EQ(store2.list().size(), std::size_t{1});
    std::filesystem::remove(path);
}

// ===========================================================================
// SiwaValidator — JWT RS256 verification (injected test JWKS)
// ===========================================================================

TEST_CASE("siwa_validator: valid token verifies")
{
    if (!gKey.ready) return;  // keygen failed — skip silently
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", 300);
    auto r = val.verifyNative(tok, {"me.test.web"});
    REQUIRE(r.ok);
    REQUIRE_EQ(r.sub,   std::string{"user_sub_1"});
    REQUIRE_EQ(r.email, std::string{"user@example.com"});
}

TEST_CASE("siwa_validator: expired token rejected")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    // Expired 60 s ago — beyond the 30 s clock-skew grace window.
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", -60);
    REQUIRE(!val.verifyNative(tok, {"me.test.web"}).ok);
}

TEST_CASE("siwa_validator: wrong aud rejected")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.evil", 300);
    REQUIRE(!val.verifyNative(tok, {"me.test.web", "me.test.ios"}).ok);
}

TEST_CASE("siwa_validator: unknown kid rejected")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key("other-kid")});  // JWKS has different-kid
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", 300);
    REQUIRE(!val.verifyNative(tok, {"me.test.web"}).ok);
}

TEST_CASE("siwa_validator: tampered payload rejected")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", 300);
    // Replace middle segment with a different payload.
    auto d1 = tok.find('.');
    auto d2 = tok.find('.', d1 + 1);
    const std::string tampered =
        tok.substr(0, d1 + 1) +
        b64urlEncodeStr("{\"iss\":\"https://appleid.apple.com\","
                        "\"aud\":\"me.test.web\","
                        "\"sub\":\"attacker\","
                        "\"email\":\"x@evil.com\","
                        "\"exp\":9999999999}") +
        tok.substr(d2);
    REQUIRE(!val.verifyNative(tampered, {"me.test.web"}).ok);
}

TEST_CASE("siwa_validator: unknown state rejected")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", 300);
    auto r = val.verifyCallback("unknown_state", tok, {"me.test.web"});
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("state") != std::string::npos);
}

TEST_CASE("siwa_validator: state consumed after one use (replay prevention)")
{
    if (!gKey.ready) return;
    // Build a valid token with the correct nonce hash embedded.
    // We can't know the nonce without extracting it — so test a weaker invariant:
    // state is consumed after one verifyCallback call (second call fails).
    ntm::SiwaConfig cfg = testCfg();
    ntm::SiwaValidator val(cfg);
    val.setTestJwks({gKey.key()});

    std::string state;
    val.beginFlow(state);  // creates pending entry

    // First call: wrong nonce hash, but state exists and is consumed.
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.web", 300,
                                            "sub1", "u@e.com", "wrong_nonce");
    val.verifyCallback(state, tok, {"me.test.web"});  // consumes state

    // Second call: state no longer exists.
    auto r2 = val.verifyCallback(state, tok, {"me.test.web"});
    REQUIRE(!r2.ok);
    REQUIRE(r2.error.find("state") != std::string::npos);
}

TEST_CASE("siwa_validator: iOS bundle id accepted as aud")
{
    if (!gKey.ready) return;
    ntm::SiwaValidator val(testCfg());
    val.setTestJwks({gKey.key()});
    const std::string tok = makeAppleToken(gKey.pkey, "tid", "me.test.ios", 300);
    // ios bundle id is in the allowedAuds list
    auto r = val.verifyNative(tok, {"me.test.web", "me.test.ios"});
    REQUIRE(r.ok);
}

TEST_CASE("siwa: SiwaConfig enabled() semantics")
{
    ntm::SiwaConfig cfg;
    REQUIRE(!cfg.enabled());
    cfg.serviceId  = "svc";
    cfg.redirectUri = "https://x.com/cb";
    REQUIRE(cfg.enabled());
}
