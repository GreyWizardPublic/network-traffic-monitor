// webauthn.cpp — WebAuthn RP implementation for ntm-server.
// Implements passkey registration, authentication, and session management.
// Only depends on OpenSSL (already linked) and the C++ standard library.

#include "webauthn.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>   // d2i_PUBKEY

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace ntm
{

// ---------------------------------------------------------------------------
// Minimal CBOR parser (just enough for WebAuthn attestationObject / COSE key)
// ---------------------------------------------------------------------------

namespace cbor
{

struct Val
{
    enum Type { UINT, NINT, BYTES, TEXT, ARRAY, MAP, OTHER };
    Type type{OTHER};
    uint64_t u{0};         // UINT: value; NINT: encoded magnitude
    std::vector<uint8_t> bytes;
    std::string text;
    std::vector<Val> items; // MAP: k0,v0,k1,v1,...  ARRAY: elem0,elem1,...

    int64_t asInt() const
    {
        if (type == UINT) return static_cast<int64_t>(u);
        if (type == NINT) return -1 - static_cast<int64_t>(u);
        return 0;
    }

    const Val *get(const std::string &key) const
    {
        if (type != MAP) return nullptr;
        for (std::size_t i = 0; i + 1 < items.size(); i += 2)
            if (items[i].type == TEXT && items[i].text == key)
                return &items[i + 1];
        return nullptr;
    }

    const Val *get(int64_t key) const
    {
        if (type != MAP) return nullptr;
        for (std::size_t i = 0; i + 1 < items.size(); i += 2)
        {
            const Val &k = items[i];
            if (k.type == UINT && static_cast<int64_t>(k.u) == key) return &items[i + 1];
            if (k.type == NINT && k.asInt() == key)                  return &items[i + 1];
        }
        return nullptr;
    }
};

static bool parse(const uint8_t *data, std::size_t len, std::size_t &pos, Val &out, int depth = 0);

static uint64_t readAdditional(const uint8_t *data, std::size_t len, std::size_t &pos,
                                uint8_t ai, bool &err)
{
    if (ai <= 23) return ai;
    if (ai == 24) { if (pos >= len) { err = true; return 0; } return data[pos++]; }
    if (ai == 25) {
        if (pos + 2 > len) { err = true; return 0; }
        uint64_t v = (uint64_t(data[pos]) << 8) | data[pos+1]; pos += 2; return v;
    }
    if (ai == 26) {
        if (pos + 4 > len) { err = true; return 0; }
        uint64_t v = (uint64_t(data[pos])<<24)|(uint64_t(data[pos+1])<<16)|
                     (uint64_t(data[pos+2])<<8)|data[pos+3]; pos += 4; return v;
    }
    if (ai == 27) {
        if (pos + 8 > len) { err = true; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | data[pos + i];
        pos += 8; return v;
    }
    err = true; return 0;
}

static bool parse(const uint8_t *data, std::size_t len, std::size_t &pos, Val &out, int depth)
{
    if (depth > 12 || pos >= len) return false;
    uint8_t ib = data[pos++];
    uint8_t mt = ib >> 5;
    uint8_t ai = ib & 0x1Fu;
    bool err = false;
    uint64_t count = readAdditional(data, len, pos, ai, err);
    if (err) return false;

    switch (mt)
    {
    case 0: out.type = Val::UINT; out.u = count; return true;
    case 1: out.type = Val::NINT; out.u = count; return true;
    case 2:
        if (count > 65536 || pos + count > len) return false;
        out.type = Val::BYTES;
        out.bytes.assign(data + pos, data + pos + (std::size_t)count);
        pos += (std::size_t)count; return true;
    case 3:
        if (count > 65536 || pos + count > len) return false;
        out.type = Val::TEXT;
        out.text.assign(reinterpret_cast<const char*>(data + pos), (std::size_t)count);
        pos += (std::size_t)count; return true;
    case 4:
        if (count > 512) return false;
        out.type = Val::ARRAY; out.u = count;
        for (uint64_t i = 0; i < count; ++i) {
            Val item;
            if (!parse(data, len, pos, item, depth + 1)) return false;
            out.items.push_back(std::move(item));
        }
        return true;
    case 5:
        if (count > 64) return false;
        out.type = Val::MAP; out.u = count;
        for (uint64_t i = 0; i < count; ++i) {
            Val k, v;
            if (!parse(data, len, pos, k, depth + 1)) return false;
            if (!parse(data, len, pos, v, depth + 1)) return false;
            out.items.push_back(std::move(k));
            out.items.push_back(std::move(v));
        }
        return true;
    case 6: { Val v; return parse(data, len, pos, v, depth + 1); } // tag: skip
    case 7: out.type = Val::OTHER; return true; // float/simple
    }
    return false;
}

} // namespace cbor

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

std::vector<uint8_t> WebAuthnRP::randomBytes(std::size_t n)
{
    std::vector<uint8_t> v(n);
    RAND_bytes(v.data(), static_cast<int>(n));
    return v;
}

std::string WebAuthnRP::toBase64url(const uint8_t *data, std::size_t len)
{
    static const char kTbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (std::size_t i = 0; i < len; i += 3)
    {
        uint32_t v = uint32_t(data[i]) << 16;
        if (i + 1 < len) v |= uint32_t(data[i+1]) << 8;
        if (i + 2 < len) v |= uint32_t(data[i+2]);
        out += kTbl[(v >> 18) & 63];
        out += kTbl[(v >> 12) & 63];
        out += (i + 1 < len) ? kTbl[(v >>  6) & 63] : '=';
        out += (i + 2 < len) ? kTbl[(v      ) & 63] : '=';
    }
    for (char &c : out)
        if (c == '+') c = '-'; else if (c == '/') c = '_';
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

std::string WebAuthnRP::toBase64url(const std::vector<uint8_t> &v)
{
    return v.empty() ? std::string{} : toBase64url(v.data(), v.size());
}

std::vector<uint8_t> WebAuthnRP::fromBase64url(const std::string &s)
{
    int8_t dec[256];
    std::memset(dec, -1, sizeof(dec));
    for (int i = 0; i < 26; ++i) { dec['A'+i] = int8_t(i); dec['a'+i] = int8_t(26+i); }
    for (int i = 0; i < 10; ++i) dec['0'+i] = int8_t(52+i);
    dec['+'] = 62; dec['/'] = 63; dec['-'] = 62; dec['_'] = 63;

    std::vector<uint8_t> out;
    out.reserve((s.size() * 3 + 3) / 4);
    uint32_t acc = 0; int bits = 0;
    for (unsigned char c : s)
    {
        int8_t v = dec[c];
        if (v < 0) continue;
        acc = (acc << 6) | uint32_t(v); bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(uint8_t((acc >> bits) & 0xFF)); }
    }
    return out;
}

std::string WebAuthnRP::bytesToHex(const uint8_t *data, std::size_t len)
{
    static const char hx[] = "0123456789abcdef";
    std::string out; out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i)
        { out += hx[data[i] >> 4]; out += hx[data[i] & 0xF]; }
    return out;
}

std::vector<uint8_t> WebAuthnRP::hexToBytes(const std::string &hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        auto hc = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hc(hex[i]), lo = hc(hex[i+1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return out;
}

std::vector<uint8_t> WebAuthnRP::sha256(const uint8_t *data, std::size_t len)
{
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(data, len, out.data());
    return out;
}

// Minimal JSON string-field extractor (no full parser needed for clientDataJSON).
std::string WebAuthnRP::jsonGetStr(const std::string &json, const std::string &key)
{
    const std::string needle = '"' + key + '"';
    std::size_t pos = 0;
    while (pos < json.size())
    {
        auto found = json.find(needle, pos);
        if (found == std::string::npos) return {};
        pos = found + needle.size();
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t'))
            ++pos;
        if (pos >= json.size() || json[pos] != '"') continue;
        ++pos;
        std::string result;
        while (pos < json.size())
        {
            char c = json[pos++];
            if (c == '"') return result;
            if (c == '\\' && pos < json.size()) {
                switch (json[pos++]) {
                    case '"':  result += '"';  break;
                    case '\\': result += '\\'; break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    default:   result += json[pos-1]; break;
                }
            } else result += c;
        }
        return {};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Constructor — load persisted state
// ---------------------------------------------------------------------------

WebAuthnRP::WebAuthnRP(WebAuthnConfig cfg) : cfg_(std::move(cfg))
{
    if (!cfg_.rpId.empty())
    {
        // Auto-derive allowed origin if none configured.
        if (cfg_.allowedOrigins.empty())
            cfg_.allowedOrigins.push_back("https://" + cfg_.rpId);

        loadCredentials();
        loadAdminCred();
    }
}

// ---------------------------------------------------------------------------
// CBOR / authData parsing
// ---------------------------------------------------------------------------

bool WebAuthnRP::extractAuthDataFromAttestationObject(const std::vector<uint8_t> &attObj,
                                                       std::vector<uint8_t> &authDataOut) const
{
    if (attObj.empty()) return false;
    std::size_t pos = 0;
    cbor::Val v;
    if (!cbor::parse(attObj.data(), attObj.size(), pos, v) || v.type != cbor::Val::MAP)
        return false;
    const cbor::Val *ad = v.get("authData");
    if (!ad || ad->type != cbor::Val::BYTES) return false;
    authDataOut = ad->bytes;
    return true;
}

bool WebAuthnRP::extractCoseP256(const uint8_t *data, std::size_t len,
                                  std::vector<uint8_t> &xOut, std::vector<uint8_t> &yOut) const
{
    std::size_t pos = 0;
    cbor::Val v;
    if (!cbor::parse(data, len, pos, v) || v.type != cbor::Val::MAP) return false;

    // kty (1) must be 2 (EC2)
    const cbor::Val *kty = v.get(int64_t(1));
    if (!kty || kty->type != cbor::Val::UINT || kty->u != 2) return false;

    // alg (3) must be -7 (ES256)
    const cbor::Val *alg = v.get(int64_t(3));
    if (!alg || alg->asInt() != -7) return false;

    // crv (-1) must be 1 (P-256)
    const cbor::Val *crv = v.get(int64_t(-1));
    if (!crv || crv->type != cbor::Val::UINT || crv->u != 1) return false;

    // x (-2): 32 bytes; y (-3): 32 bytes
    const cbor::Val *x = v.get(int64_t(-2));
    const cbor::Val *y = v.get(int64_t(-3));
    if (!x || x->type != cbor::Val::BYTES || x->bytes.size() != 32) return false;
    if (!y || y->type != cbor::Val::BYTES || y->bytes.size() != 32) return false;

    xOut = x->bytes;
    yOut = y->bytes;
    return true;
}

bool WebAuthnRP::parseAuthData(const std::vector<uint8_t> &authData,
                                std::string &credIdOut,
                                std::vector<uint8_t> &pubXOut,
                                std::vector<uint8_t> &pubYOut,
                                uint32_t &signCountOut,
                                bool expectAT) const
{
    // Layout: 32 rpIdHash | 1 flags | 4 signCount | [AT data if bit6 set]
    if (authData.size() < 37) return false;

    // Verify RP ID hash
    auto rpHash = sha256(reinterpret_cast<const uint8_t*>(cfg_.rpId.data()), cfg_.rpId.size());
    if (std::memcmp(authData.data(), rpHash.data(), 32) != 0) return false;

    uint8_t flags = authData[32];
    bool upSet = (flags & 0x01u) != 0;  // User Present
    bool atSet = (flags & 0x40u) != 0;  // Attested credential data present

    if (!upSet) return false; // user presence is mandatory

    signCountOut = (uint32_t(authData[33]) << 24) | (uint32_t(authData[34]) << 16) |
                   (uint32_t(authData[35]) <<  8) |  uint32_t(authData[36]);

    if (!atSet) return !expectAT;

    // Parse attested credential data starting at byte 37
    std::size_t off = 37;
    if (authData.size() < off + 16 + 2) return false;
    off += 16; // skip AAGUID

    uint16_t credIdLen = (uint16_t(authData[off]) << 8) | authData[off + 1];
    off += 2;
    if (authData.size() < off + credIdLen) return false;
    credIdOut = toBase64url(authData.data() + off, credIdLen);
    off += credIdLen;

    if (!extractCoseP256(authData.data() + off, authData.size() - off, pubXOut, pubYOut))
        return false;

    return true;
}

// ---------------------------------------------------------------------------
// ECDSA P-256 verification via SubjectPublicKeyInfo DER + d2i_PUBKEY
// ---------------------------------------------------------------------------

bool WebAuthnRP::verifyEcdsaP256(const std::vector<uint8_t> &pubX,
                                  const std::vector<uint8_t> &pubY,
                                  const std::vector<uint8_t> &msg,
                                  const std::vector<uint8_t> &derSig) const
{
    if (pubX.size() != 32 || pubY.size() != 32 || derSig.empty()) return false;

    // Fixed SubjectPublicKeyInfo DER prefix for P-256 (91 bytes total):
    // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { 04 || x || y } }
    static const uint8_t kSpkiPrefix[27] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00, 0x04  // BIT STRING header + uncompressed point tag
    };

    uint8_t spki[91];
    std::memcpy(spki,      kSpkiPrefix,  27);
    std::memcpy(spki + 27, pubX.data(),  32);
    std::memcpy(spki + 59, pubY.data(),  32);

    const uint8_t *ptr = spki;
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &ptr, 91);
    if (!pkey) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx &&
              EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
              EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) == 1 &&
              EVP_DigestVerifyFinal(ctx, derSig.data(), derSig.size()) == 1;

    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

std::string WebAuthnRP::beginRegistration(std::string &sessionKey)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sweepExpired();

    if (!adminCred_.has_value())
        return "{\"error\":\"admin credentials not configured\"}";

    auto wChallenge = randomBytes(32);
    auto adminNonce = randomBytes(32);
    sessionKey = toBase64url(randomBytes(24));

    auto expiry = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    pendingRegs_[sessionKey] = { wChallenge, adminNonce, expiry };

    std::string j;
    j  = "{\"session_key\":\""; j += sessionKey;
    j += "\",\"challenge\":\"";   j += toBase64url(wChallenge);
    j += "\",\"admin_nonce\":\""; j += toBase64url(adminNonce);
    j += "\",\"pbkdf2_salt\":\""; j += toBase64url(adminCred_->salt);
    j += "\",\"pbkdf2_iterations\":"; j += std::to_string(adminCred_->iterations);
    j += ",\"rp_id\":\"";         j += cfg_.rpId;
    j += "\",\"rp_name\":\"";     j += cfg_.rpName.empty() ? cfg_.rpId : cfg_.rpName;
    j += "\",\"user_id\":\"";     j += toBase64url(randomBytes(16));
    j += "\"}";
    return j;
}

std::string WebAuthnRP::completeRegistration(const std::string &sessionKey,
                                              const std::string &adminProofHex,
                                              const std::string &attestationObjectB64,
                                              const std::string &clientDataJsonB64,
                                              const std::string &label)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sweepExpired();

    auto it = pendingRegs_.find(sessionKey);
    if (it == pendingRegs_.end()) return "invalid or expired session";

    const PendingReg &pr = it->second;
    if (std::chrono::steady_clock::now() > pr.expiry)
    {
        pendingRegs_.erase(it);
        return "session expired";
    }

    // Verify admin PBKDF2 proof: expected = HMAC-SHA256(storedHash, adminNonce)
    if (!adminCred_.has_value()) { pendingRegs_.erase(it); return "admin not configured"; }
    {
        uint8_t expected[32];
        unsigned elen = 32;
        HMAC(EVP_sha256(),
             adminCred_->hash.data(), static_cast<int>(adminCred_->hash.size()),
             pr.adminNonce.data(),    static_cast<int>(pr.adminNonce.size()),
             expected, &elen);

        auto submitted = hexToBytes(adminProofHex);
        bool proofOk = (submitted.size() == 32) &&
                       (CRYPTO_memcmp(submitted.data(), expected, 32) == 0);
        if (!proofOk) { pendingRegs_.erase(it); return "admin proof incorrect"; }
    }

    // Decode and parse clientDataJSON
    auto cdJsonBytes = fromBase64url(clientDataJsonB64);
    if (cdJsonBytes.empty()) { pendingRegs_.erase(it); return "bad clientDataJSON"; }
    std::string cdJson(cdJsonBytes.begin(), cdJsonBytes.end());

    // Verify type
    if (jsonGetStr(cdJson, "type") != "webauthn.create")
        { pendingRegs_.erase(it); return "clientDataJSON type mismatch"; }

    // Verify WebAuthn challenge
    std::string gotChallenge = jsonGetStr(cdJson, "challenge");
    if (fromBase64url(gotChallenge) != pr.webauthnChallenge)
        { pendingRegs_.erase(it); return "challenge mismatch"; }

    // Verify origin
    std::string origin = jsonGetStr(cdJson, "origin");
    bool originOk = false;
    for (const auto &ao : cfg_.allowedOrigins)
        if (ao == origin) { originOk = true; break; }
    if (!originOk) { pendingRegs_.erase(it); return "origin not allowed: " + origin; }

    // Decode and parse attestationObject
    auto attObj = fromBase64url(attestationObjectB64);
    std::vector<uint8_t> authData;
    if (!extractAuthDataFromAttestationObject(attObj, authData))
        { pendingRegs_.erase(it); return "failed to parse attestationObject"; }

    // Parse authData: verify RP ID hash, extract credential
    std::string credId;
    std::vector<uint8_t> pubX, pubY;
    uint32_t signCount = 0;
    if (!parseAuthData(authData, credId, pubX, pubY, signCount, true))
        { pendingRegs_.erase(it); return "authData validation failed"; }

    // Reject duplicate credential IDs
    for (const auto &c : credentials_)
        if (c.credId == credId) { pendingRegs_.erase(it); return "credential already registered"; }

    PasskeyCredential cred;
    cred.credId    = credId;
    cred.pubkeyX   = toBase64url(pubX);
    cred.pubkeyY   = toBase64url(pubY);
    cred.signCount = signCount;
    cred.label     = label.empty() ? "My Device" : label;

    credentials_.push_back(cred);
    saveCredentials();
    pendingRegs_.erase(it);
    return "";  // success
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

std::string WebAuthnRP::beginAuthentication(std::string &sessionKey)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sweepExpired();

    auto challenge = randomBytes(32);
    sessionKey = toBase64url(randomBytes(24));
    auto expiry = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    pendingAuths_[sessionKey] = { challenge, expiry };

    std::string j;
    j  = "{\"session_key\":\""; j += sessionKey;
    j += "\",\"challenge\":\"";  j += toBase64url(challenge);
    j += "\",\"rp_id\":\"";      j += cfg_.rpId;
    j += "\",\"credential_ids\":[";
    bool first = true;
    for (const auto &c : credentials_)
    {
        if (!first) j += ',';
        j += '"'; j += c.credId; j += '"';
        first = false;
    }
    j += "]}";
    return j;
}

std::string WebAuthnRP::completeAuthentication(const std::string &sessionKey,
                                                const std::string &credentialIdB64,
                                                const std::string &authenticatorDataB64,
                                                const std::string &clientDataJsonB64,
                                                const std::string &signatureB64,
                                                std::string &errorOut)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sweepExpired();

    auto it = pendingAuths_.find(sessionKey);
    if (it == pendingAuths_.end()) { errorOut = "invalid or expired session"; return {}; }

    const PendingAuth &pa = it->second;
    if (std::chrono::steady_clock::now() > pa.expiry)
    {
        pendingAuths_.erase(it);
        errorOut = "session expired"; return {};
    }

    // Decode clientDataJSON
    auto cdJsonBytes = fromBase64url(clientDataJsonB64);
    if (cdJsonBytes.empty()) { pendingAuths_.erase(it); errorOut = "bad clientDataJSON"; return {}; }
    std::string cdJson(cdJsonBytes.begin(), cdJsonBytes.end());

    if (jsonGetStr(cdJson, "type") != "webauthn.get")
        { pendingAuths_.erase(it); errorOut = "type mismatch"; return {}; }

    std::string gotChallenge = jsonGetStr(cdJson, "challenge");
    if (fromBase64url(gotChallenge) != pa.challenge)
        { pendingAuths_.erase(it); errorOut = "challenge mismatch"; return {}; }

    std::string origin = jsonGetStr(cdJson, "origin");
    bool originOk = false;
    for (const auto &ao : cfg_.allowedOrigins)
        if (ao == origin) { originOk = true; break; }
    if (!originOk) { pendingAuths_.erase(it); errorOut = "origin not allowed: " + origin; return {}; }

    // Find credential
    auto authDataBytes = fromBase64url(authenticatorDataB64);
    std::string credId;
    std::vector<uint8_t> pubX, pubY;
    uint32_t signCount = 0;
    if (!parseAuthData(authDataBytes, credId, pubX, pubY, signCount, false))
    {
        // authData for authentication may not have AT flag; parseAuthData returns credId="" in that case
        // We match by the credentialIdB64 from the assertion instead
        credId = credentialIdB64;
    }

    // Find matching stored credential (try both the authData-extracted ID and the response field)
    PasskeyCredential *stored = nullptr;
    for (auto &c : credentials_)
    {
        if (c.credId == credentialIdB64 || c.credId == credId)
        {
            stored = &c;
            break;
        }
    }
    if (!stored) { pendingAuths_.erase(it); errorOut = "credential not found"; return {}; }

    pubX = fromBase64url(stored->pubkeyX);
    pubY = fromBase64url(stored->pubkeyY);

    // Construct message: authenticatorData || SHA-256(clientDataJSON)
    auto cdHash = sha256(cdJsonBytes.data(), cdJsonBytes.size());
    std::vector<uint8_t> msg;
    msg.reserve(authDataBytes.size() + 32);
    msg.insert(msg.end(), authDataBytes.begin(), authDataBytes.end());
    msg.insert(msg.end(), cdHash.begin(), cdHash.end());

    auto derSig = fromBase64url(signatureB64);
    if (!verifyEcdsaP256(pubX, pubY, msg, derSig))
        { pendingAuths_.erase(it); errorOut = "signature verification failed"; return {}; }

    // Update sign count (allow 0 from some platform authenticators that don't track it)
    if (signCount != 0 && signCount <= stored->signCount)
    {
        pendingAuths_.erase(it);
        errorOut = "sign count replay detected";
        return {};
    }
    if (signCount != 0) stored->signCount = signCount;
    saveCredentials();

    pendingAuths_.erase(it);

    // Issue a session token
    auto token = toBase64url(randomBytes(32));
    auto expiry = std::chrono::steady_clock::now() +
                  std::chrono::hours(cfg_.sessionTtlHours);
    sessions_[token] = { expiry };
    return token;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

bool WebAuthnRP::isValidSession(const std::string &token) const
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = sessions_.find(token);
    if (it == sessions_.end()) return false;
    return std::chrono::steady_clock::now() <= it->second.expiry;
}

void WebAuthnRP::invalidateSession(const std::string &token)
{
    std::lock_guard<std::mutex> lk(mtx_);
    sessions_.erase(token);
}

// ---------------------------------------------------------------------------
// Admin credential management
// ---------------------------------------------------------------------------

bool WebAuthnRP::hasAdminCred() const
{
    std::lock_guard<std::mutex> lk(mtx_);
    return adminCred_.has_value();
}

bool WebAuthnRP::verifyAdminPassword(const std::string &plaintext) const
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (!adminCred_.has_value()) return false;
    std::vector<uint8_t> derived(32);
    if (PKCS5_PBKDF2_HMAC(plaintext.data(), static_cast<int>(plaintext.size()),
                           adminCred_->salt.data(), static_cast<int>(adminCred_->salt.size()),
                           adminCred_->iterations, EVP_sha256(), 32, derived.data()) != 1)
        return false;
    return CRYPTO_memcmp(derived.data(), adminCred_->hash.data(), 32) == 0;
}

std::string WebAuthnRP::migrateAdminPassword(const std::string &plaintext)
{
    if (cfg_.adminCredFile.empty()) return "webauthn_admin_cred_file not configured";

    auto salt = randomBytes(16);
    std::vector<uint8_t> hash(32);
    if (PKCS5_PBKDF2_HMAC(plaintext.data(), static_cast<int>(plaintext.size()),
                           salt.data(), static_cast<int>(salt.size()),
                           200000, EVP_sha256(), 32, hash.data()) != 1)
        return "PBKDF2 failed";

    // Write JSON: {"version":1,"hash":"<b64url>","salt":"<b64url>","iterations":200000}
    std::ofstream f(cfg_.adminCredFile, std::ios::trunc);
    if (!f) return "cannot write " + cfg_.adminCredFile;
    f << "{\"version\":1,\"hash\":\"" << toBase64url(hash)
      << "\",\"salt\":\"" << toBase64url(salt)
      << "\",\"iterations\":200000}\n";
    f.close();

    std::lock_guard<std::mutex> lk(mtx_);
    adminCred_ = AdminCred{ hash, salt, 200000 };
    return "";
}

void WebAuthnRP::loadAdminCred()
{
    if (cfg_.adminCredFile.empty()) return;
    std::ifstream f(cfg_.adminCredFile);
    if (!f) return;
    std::string json((std::istreambuf_iterator<char>(f)), {});

    std::string hashB64 = jsonGetStr(json, "hash");
    std::string saltB64 = jsonGetStr(json, "salt");

    auto hash = fromBase64url(hashB64);
    auto salt = fromBase64url(saltB64);
    if (hash.size() != 32 || salt.size() < 8) return;

    AdminCred ac;
    ac.hash = hash;
    ac.salt = salt;
    ac.iterations = 200000; // we always write 200000; ignore stored value for robustness

    std::lock_guard<std::mutex> lk(mtx_);
    adminCred_ = ac;
}

// ---------------------------------------------------------------------------
// Credential persistence
// ---------------------------------------------------------------------------

void WebAuthnRP::loadCredentials()
{
    if (cfg_.credentialsFile.empty()) return;
    std::ifstream f(cfg_.credentialsFile);
    if (!f) return;
    std::string json((std::istreambuf_iterator<char>(f)), {});

    // Parse the "credentials" array manually: scan for objects between [ and ]
    auto arrayStart = json.find("\"credentials\"");
    if (arrayStart == std::string::npos) return;
    arrayStart = json.find('[', arrayStart);
    if (arrayStart == std::string::npos) return;

    std::lock_guard<std::mutex> lk(mtx_);
    credentials_.clear();

    std::size_t pos = arrayStart + 1;
    while (pos < json.size())
    {
        // Skip whitespace and commas
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ',' ||
                                      json[pos] == '\n' || json[pos] == '\r' ||
                                      json[pos] == '\t')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        if (json[pos] != '{') { ++pos; continue; }

        // Find matching closing brace
        auto objStart = pos;
        int depth = 0;
        bool inStr = false; char prev = 0;
        while (pos < json.size())
        {
            char c = json[pos++];
            if (c == '"' && prev != '\\') inStr = !inStr;
            if (!inStr) { if (c == '{') ++depth; else if (c == '}') { --depth; if (!depth) break; } }
            prev = c;
        }
        std::string obj = json.substr(objStart, pos - objStart);

        PasskeyCredential cred;
        cred.credId    = jsonGetStr(obj, "id");
        cred.pubkeyX   = jsonGetStr(obj, "x");
        cred.pubkeyY   = jsonGetStr(obj, "y");
        cred.label     = jsonGetStr(obj, "label");

        // sign_count is numeric; parse it manually
        const std::string sc_key = "\"sign_count\"";
        auto sc_pos = obj.find(sc_key);
        if (sc_pos != std::string::npos) {
            sc_pos += sc_key.size();
            while (sc_pos < obj.size() && (obj[sc_pos] == ':' || obj[sc_pos] == ' ')) ++sc_pos;
            try { cred.signCount = static_cast<uint32_t>(std::stoul(obj.substr(sc_pos))); }
            catch (...) {}
        }

        if (!cred.credId.empty() && !cred.pubkeyX.empty() && !cred.pubkeyY.empty())
            credentials_.push_back(std::move(cred));
    }
}

void WebAuthnRP::saveCredentials() const
{
    if (cfg_.credentialsFile.empty()) return;
    std::ofstream f(cfg_.credentialsFile, std::ios::trunc);
    if (!f)
    {
        fprintf(stderr, "ntm WebAuthn: cannot write credentials file '%s': %s\n",
                cfg_.credentialsFile.c_str(), strerror(errno));
        return;
    }

    f << "{\"version\":1,\"credentials\":[\n";
    bool first = true;
    for (const auto &c : credentials_)
    {
        if (!first) f << ",\n";
        f << "  {\"id\":\"" << c.credId << "\",\"x\":\"" << c.pubkeyX
          << "\",\"y\":\"" << c.pubkeyY << "\",\"sign_count\":" << c.signCount
          << ",\"label\":\"" << c.label << "\"}";
        first = false;
    }
    f << "\n]}\n";
}

// ---------------------------------------------------------------------------
// Credential listing / deletion
// ---------------------------------------------------------------------------

std::vector<PasskeyCredential> WebAuthnRP::listCredentials() const
{
    std::lock_guard<std::mutex> lk(mtx_);
    return credentials_;
}

bool WebAuthnRP::deleteCredential(const std::string &credId)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::find_if(credentials_.begin(), credentials_.end(),
                           [&](const PasskeyCredential &c){ return c.credId == credId; });
    if (it == credentials_.end()) return false;
    credentials_.erase(it);
    saveCredentials();
    return true;
}

// ---------------------------------------------------------------------------
// AASA
// ---------------------------------------------------------------------------

std::string WebAuthnRP::aasaJson() const
{
    if (cfg_.iosAppId.empty()) return {};
    std::string j;
    j  = "{\"webcredentials\":{\"apps\":[\"";
    j += cfg_.iosAppId;
    j += "\"]}}";
    return j;
}

// ---------------------------------------------------------------------------
// Sweep expired pending sessions
// ---------------------------------------------------------------------------

void WebAuthnRP::sweepExpired()
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pendingRegs_.begin(); it != pendingRegs_.end(); )
        it = (now > it->second.expiry) ? pendingRegs_.erase(it) : std::next(it);
    for (auto it = pendingAuths_.begin(); it != pendingAuths_.end(); )
        it = (now > it->second.expiry) ? pendingAuths_.erase(it) : std::next(it);
    for (auto it = sessions_.begin(); it != sessions_.end(); )
        it = (now > it->second.expiry) ? sessions_.erase(it) : std::next(it);
}

} // namespace ntm
