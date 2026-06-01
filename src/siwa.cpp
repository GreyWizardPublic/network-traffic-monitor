// siwa.cpp — Sign in with Apple: admin identity store + JWKS cache + JWT verification.
// Implements SiwaAdminStore and SiwaValidator declared in siwa.hpp.

#include "siwa.hpp"

#include <curl/curl.h>  // libcurl — already linked into ntm-server; better CA handling than httplib

#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <sys/stat.h>   // chmod()
#include <thread>       // std::this_thread::sleep_for

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace ntm
{

// ---------------------------------------------------------------------------
// SiwaAdminStore
// ---------------------------------------------------------------------------

// Trim and split a comma-separated list into tokens (lowercased for emails).
static std::vector<std::string> splitCsv(const std::string &csv, bool lowercase)
{
    std::vector<std::string> out;
    std::istringstream iss(csv);
    std::string tok;
    while (std::getline(iss, tok, ','))
    {
        while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
        while (!tok.empty() && tok.back()  == ' ') tok.pop_back();
        if (tok.empty()) continue;
        if (lowercase)
            for (char &c : tok) c = (char)std::tolower((unsigned char)c);
        out.push_back(tok);
    }
    return out;
}

SiwaAdminStore::SiwaAdminStore(const std::string &filePath,
                                 const std::string &configEmails,
                                 const std::string &configSubs)
    : filePath_(filePath)
{
    load();

    // Seed email-based admin entries.
    for (const auto &email : splitCsv(configEmails, /*lowercase=*/true))
    {
        bool found = false;
        for (const auto &id : identities_)
            if (siwaEmailsEqual(id.email, email)) { found = true; break; }
        if (!found)
            identities_.push_back({email, {}});
    }

    // Seed sub-only entries (siwa_admin_subs). These are for operators who use
    // "Hide My Email" and obtained their Apple sub from the server logs.
    // Stored as records with an empty email — matched by sub only.
    for (const auto &sub : splitCsv(configSubs, /*lowercase=*/false))
    {
        bool found = false;
        for (const auto &id : identities_)
            if (id.sub == sub) { found = true; break; }
        if (!found)
            identities_.push_back({"", sub});
    }

    // Persist if we added anything (no lock needed — constructor is single-threaded).
    if (!filePath_.empty()) save();
}

void SiwaAdminStore::load()
{
    if (filePath_.empty()) return;
    std::ifstream f(filePath_);
    if (!f) return;  // file may not exist yet — that is normal on first run

    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    // Simple hand-rolled parse of [{"email":"...","sub":"..."},...]
    std::size_t pos = json.find('[');
    if (pos == std::string::npos) return;
    ++pos;
    while (pos < json.size())
    {
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\n' ||
                                      json[pos] == '\r' || json[pos] == ',')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        if (json[pos] != '{') { ++pos; continue; }
        auto end = json.find('}', pos);
        if (end == std::string::npos) break;
        const std::string obj = json.substr(pos, end - pos + 1);
        SiwaAdminIdentity id;
        id.email = jwtGetStr(obj, "email");
        id.sub   = jwtGetStr(obj, "sub");
        // Normalise email to lowercase.
        for (char &c : id.email) c = (char)std::tolower((unsigned char)c);
        if (!id.email.empty())
            identities_.push_back(std::move(id));
        pos = end + 1;
    }
}

// Write a snapshot of identities to disk (no lock held — caller must snapshot first).
static void saveSnapshot(const std::string &filePath,
                          const std::vector<ntm::SiwaAdminIdentity> &snap)
{
    if (filePath.empty()) return;
    std::ofstream f(filePath, std::ios::trunc);
    if (!f)
    {
        fprintf(stderr, "ntm siwa: cannot write admin file '%s': %s\n",
                filePath.c_str(), strerror(errno));
        return;
    }
    f << "[\n";
    bool first = true;
    for (const auto &id : snap)
    {
        if (!first) f << ",\n";
        f << "  {\"email\":\"" << id.email << "\",\"sub\":\"" << id.sub << "\"}";
        first = false;
    }
    f << "\n]\n";
    f.close();
    chmod(filePath.c_str(), 0600);
}

void SiwaAdminStore::save() const
{
    // Take snapshot under lock, then write outside lock so I/O does not block
    // concurrent auth requests.
    std::vector<SiwaAdminIdentity> snap;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        snap = identities_;
    }
    saveSnapshot(filePath_, snap);
}

bool SiwaAdminStore::matchAndPin(const std::string &sub, const std::string &email)
{
    std::vector<SiwaAdminIdentity> snap;
    bool needsSave = false;
    bool isAdmin   = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        int idx = matchAdminIdentity(identities_, sub, email);
        if (idx >= 0)
        {
            isAdmin = true;
            if (identities_[idx].sub.empty())
            {
                identities_[idx].sub = sub;
                needsSave = true;
                snap = identities_;  // snapshot under lock for write outside lock
            }
        }
    }
    // File I/O outside the lock — no blocking of concurrent auth requests.
    if (needsSave) saveSnapshot(filePath_, snap);
    return isAdmin;
}

std::vector<SiwaAdminIdentity> SiwaAdminStore::list() const
{
    std::lock_guard<std::mutex> lk(mtx_);
    return identities_;
}

// ---------------------------------------------------------------------------
// SiwaValidator — helpers
// ---------------------------------------------------------------------------

std::string SiwaValidator::sha256Hex(const std::string &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(), hash);
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
    return std::string(hex, SHA256_DIGEST_LENGTH * 2);
}

std::string SiwaValidator::randomHex(std::size_t nBytes)
{
    std::vector<unsigned char> buf(nBytes);
    RAND_bytes(buf.data(), (int)nBytes);
    std::string out;
    out.reserve(nBytes * 2);
    for (auto b : buf)
    {
        char h[3];
        std::snprintf(h, sizeof(h), "%02x", b);
        out += h;
    }
    return out;
}

std::vector<SiwaJwksKey> SiwaValidator::parseJwksJson(const std::string &json)
{
    std::vector<SiwaJwksKey> keys;
    auto pos = json.find("\"keys\"");
    if (pos == std::string::npos) return keys;
    pos = json.find('[', pos);
    if (pos == std::string::npos) return keys;
    ++pos;
    while (pos < json.size())
    {
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\r' ||
                json[pos] == ',')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        if (json[pos] != '{') { ++pos; continue; }
        auto end = json.find('}', pos);
        if (end == std::string::npos) break;
        const std::string obj = json.substr(pos, end - pos + 1);
        SiwaJwksKey k;
        k.kid = jwtGetStr(obj, "kid");
        k.n   = jwtGetStr(obj, "n");
        k.e   = jwtGetStr(obj, "e");
        if (!k.n.empty() && !k.e.empty())
            keys.push_back(std::move(k));
        pos = end + 1;
    }
    return keys;
}

// ---------------------------------------------------------------------------
// SiwaValidator — JWKS fetch
// ---------------------------------------------------------------------------

SiwaValidator::SiwaValidator(const SiwaConfig &cfg) : cfg_(cfg) {}

void SiwaValidator::setTestJwks(const std::vector<SiwaJwksKey> &keys)
{
    std::lock_guard<std::mutex> lk(mtx_);
    jwksKeys_ = keys;
    // Set expiry far in the future so the cached keys are always used.
    jwksExpiry_ = std::chrono::steady_clock::now() + std::chrono::hours(24 * 365);
    testMode_ = true;
}

// libcurl write callback — appends received data to a std::string.
static std::size_t curlAppend(char *ptr, std::size_t size, std::size_t nmemb, void *ud)
{
    auto *out = static_cast<std::string *>(ud);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool SiwaValidator::ensureJwks()
{
    // Already fresh?
    if (!jwksKeys_.empty() &&
        std::chrono::steady_clock::now() < jwksExpiry_) return true;
    if (testMode_) return !jwksKeys_.empty();

    // Prevent concurrent threads from all triggering a 15 s network fetch.
    // Only the first thread fetches; others wait up to 20 s and reuse the result.
    bool expected = false;
    if (!jwksFetchInProgress_.compare_exchange_strong(expected, true))
    {
        // Another thread is already fetching. Wait briefly and return current state.
        for (int i = 0; i < 200; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!jwksFetchInProgress_.load()) break;
        }
        return !jwksKeys_.empty();
    }

    // Fetch Apple JWKS via libcurl — libcurl uses the system CA bundle and works
    // on all Linux distributions without any extra configuration. httplib's SSLClient
    // requires manual CA path configuration and may fail silently on some hosts.
    std::string body;
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr, "ntm siwa: curl_easy_init failed\n");
        jwksFetchInProgress_.store(false);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_URL, "https://appleid.apple.com/auth/keys");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlAppend);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ntm-server/2 (SIWA JWKS fetch)");

    CURLcode rc = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK)
    {
        fprintf(stderr,
                "ntm siwa: JWKS fetch failed: %s. "
                "Ensure the server can reach appleid.apple.com:443 outbound.\n",
                curl_easy_strerror(rc));
        jwksFetchInProgress_.store(false);
        return false;
    }
    if (httpCode != 200)
    {
        fprintf(stderr, "ntm siwa: JWKS fetch returned HTTP %ld\n", httpCode);
        jwksFetchInProgress_.store(false);
        return false;
    }
    auto parsed = parseJwksJson(body);
    if (parsed.empty())
    {
        fprintf(stderr, "ntm siwa: JWKS response contained no usable RSA keys\n");
        jwksFetchInProgress_.store(false);
        return false;
    }
    jwksKeys_   = std::move(parsed);
    jwksExpiry_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
    jwksFetchInProgress_.store(false);
    return true;
}

// ---------------------------------------------------------------------------
// SiwaValidator — RSA-SHA256 verification (RS256)
// ---------------------------------------------------------------------------

bool SiwaValidator::rsaVerifyRS256(const SiwaJwksKey &key,
                                    const std::string &signingInput,
                                    const std::string &sigB64) const
{
    // Decode modulus, exponent, and signature from base64url.
    auto nBytes   = siwaBase64urlDecode(key.n);
    auto eBytes   = siwaBase64urlDecode(key.e);
    auto sigBytes = siwaBase64urlDecode(sigB64);
    if (nBytes.empty() || eBytes.empty() || sigBytes.empty()) return false;

    // Build EVP_PKEY from raw n/e using the OpenSSL 3.x EVP_PKEY_fromdata API.
    BIGNUM *n_bn = BN_bin2bn(nBytes.data(), (int)nBytes.size(), nullptr);
    BIGNUM *e_bn = BN_bin2bn(eBytes.data(), (int)eBytes.size(), nullptr);
    if (!n_bn || !e_bn) { BN_free(n_bn); BN_free(e_bn); return false; }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) { BN_free(n_bn); BN_free(e_bn); return false; }
    bool paramOk = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn) == 1 &&
                    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn) == 1);
    OSSL_PARAM *params = paramOk ? OSSL_PARAM_BLD_to_param(bld) : nullptr;
    OSSL_PARAM_BLD_free(bld);
    BN_free(n_bn);
    BN_free(e_bn);
    if (!params) return false;

    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY *pkey = nullptr;
    if (pkctx &&
        EVP_PKEY_fromdata_init(pkctx) == 1 &&
        EVP_PKEY_fromdata(pkctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1)
    { /* pkey ready */ }
    EVP_PKEY_CTX_free(pkctx);
    OSSL_PARAM_free(params);
    if (!pkey) return false;

    // Verify RS256 (PKCS#1 v1.5, SHA-256).
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    bool ok = false;
    if (mdctx)
    {
        if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(mdctx,
                                   signingInput.data(),
                                   signingInput.size()) == 1)
        {
            ok = (EVP_DigestVerifyFinal(mdctx, sigBytes.data(), sigBytes.size()) == 1);
        }
        EVP_MD_CTX_free(mdctx);
    }
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// SiwaValidator — JWT verification entry point
// ---------------------------------------------------------------------------

SiwaValidator::VerifyResult SiwaValidator::verifyJwt(
    const std::string &idToken,
    const std::vector<std::string> &allowedAuds,
    const std::string &expectedNonceHash)
{
    // 1. Parse JWT structure.
    auto parts = parseJwt(idToken);
    if (!parts) return {false, {}, {}, "malformed JWT"};

    // 2. Get kid from header.
    const std::string kid = jwtGetStr(parts->headerJson, "kid");
    const std::string alg = jwtGetStr(parts->headerJson, "alg");
    if (alg != "RS256") return {false, {}, {}, "unsupported alg: " + alg};

    // 3. Ensure JWKS is loaded.
    if (!ensureJwks()) return {false, {}, {}, "JWKS unavailable"};

    // 4. Find the key with matching kid.
    const SiwaJwksKey *matchedKey = nullptr;
    for (const auto &k : jwksKeys_)
        if (k.kid == kid) { matchedKey = &k; break; }

    if (!matchedKey)
    {
        // kid not found — try refreshing JWKS once (Apple rotates keys).
        jwksKeys_.clear();
        if (!ensureJwks()) return {false, {}, {}, "JWKS refresh failed"};
        for (const auto &k : jwksKeys_)
            if (k.kid == kid) { matchedKey = &k; break; }
        if (!matchedKey)
            return {false, {}, {}, "no JWKS key matching kid=" + kid};
    }

    // 5. Verify RS256 signature.
    if (!rsaVerifyRS256(*matchedKey, parts->signingInput, parts->sigB64))
        return {false, {}, {}, "signature verification failed"};

    // 6. Validate standard claims.
    const long long now = (long long)std::time(nullptr);
    std::string claimErr = validateAppleClaims(
        parts->payloadJson, allowedAuds, expectedNonceHash, now);
    if (!claimErr.empty()) return {false, {}, {}, claimErr};

    // 7. Extract identity.
    const std::string sub   = jwtGetStr(parts->payloadJson, "sub");
    const std::string email = jwtGetStr(parts->payloadJson, "email");
    if (sub.empty()) return {false, {}, {}, "missing sub claim"};

    return {true, sub, email, {}};
}

// ---------------------------------------------------------------------------
// SiwaValidator — public flow methods
// ---------------------------------------------------------------------------

void SiwaValidator::sweepPending()
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pending_.begin(); it != pending_.end(); )
        it = (now > it->second.expiry) ? pending_.erase(it) : std::next(it);
}

std::string SiwaValidator::beginFlow(std::string &stateOut)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sweepPending();

    const std::string state    = randomHex(16);
    const std::string nonceRaw = randomHex(32);

    pending_[state] = { nonceRaw,
                        std::chrono::steady_clock::now() + std::chrono::minutes(10) };
    stateOut = state;

    // Send SHA-256 of the raw nonce to Apple (Apple will include this hash in the JWT).
    const std::string nonceHash = sha256Hex(nonceRaw);
    return buildAuthorizeUrl(cfg_.serviceId, cfg_.redirectUri, state, nonceHash);
}

SiwaValidator::VerifyResult SiwaValidator::verifyCallback(
    const std::string &state,
    const std::string &idToken,
    const std::vector<std::string> &allowedAuds)
{
    std::string expectedNonceHash;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        sweepPending();
        auto it = pending_.find(state);
        if (it == pending_.end())
            return {false, {}, {}, "unknown or expired state"};
        expectedNonceHash = sha256Hex(it->second.nonceRaw);
        pending_.erase(it);  // consume — one-time use
    }
    return verifyJwt(idToken, allowedAuds, expectedNonceHash);
}

SiwaValidator::VerifyResult SiwaValidator::verifyNative(
    const std::string &idToken,
    const std::vector<std::string> &allowedAuds)
{
    // Native iOS flow: no nonce round-trip. Guard against token replay using a
    // short-lived cache keyed on (sub, exp). A captured id_token cannot be reused
    // within its validity window.
    std::lock_guard<std::mutex> lk(mtx_);

    // Quick pre-check: parse sub + exp before full verification to detect replays early.
    auto parts = parseJwt(idToken);
    if (!parts) return {false, {}, {}, "malformed JWT"};
    const std::string sub = jwtGetStr(parts->payloadJson, "sub");
    const long long   exp = jwtGetLong(parts->payloadJson, "exp");

    if (!sub.empty() && exp > 0)
    {
        // Prune stale replay-cache entries (beyond exp + 60 s grace).
        const long long now = static_cast<long long>(std::time(nullptr));
        for (auto it = nativeReplayCache_.begin(); it != nativeReplayCache_.end(); )
            it = (now > it->second + 60) ? nativeReplayCache_.erase(it) : std::next(it);

        const std::string replayKey = sub + ":" + std::to_string(exp);
        if (nativeReplayCache_.count(replayKey))
            return {false, {}, {}, "token replay detected"};
    }

    auto result = verifyJwt(idToken, allowedAuds, {} /* no nonce check */);

    // Record this token as seen so it cannot be replayed.
    if (result.ok && !sub.empty() && exp > 0)
        nativeReplayCache_[sub + ":" + std::to_string(exp)] = exp;

    return result;
}

} // namespace ntm
