#pragma once
// server_upgrade.hpp — pure logic for ntm-server binary auto-upgrade.
//
// ALL functions here are pure logic: no syslog, no global server state.
// OpenSSL EVP is used for SHA3-256 and ML-DSA-65 verification only.
// This makes every piece testable independently of the running server.
//
// Components:
//   Semver               — version struct with full comparison operators
//   parseSemver          — parse "1.17.0" → Semver
//   sha3_256             — SHA3-256 hash via OpenSSL EVP
//   base64Decode         — pure-C++ base64 decoder (no OpenSSL BIO)
//   verifyUpgradeAuth    — ML-DSA-65 verify over (nonce_bytes || binary_sha3)
//   NonceStore           — thread-safe, single-use, TTL-based nonce store
//   writeUpgradeAtomically — atomic binary + sig replacement via rename(2)

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

namespace ntm::upgrade
{

// ---------------------------------------------------------------------------
// Semver
// ---------------------------------------------------------------------------

struct Semver
{
    unsigned major{0};
    unsigned minor{0};
    unsigned patch{0};
    bool     valid{false};

    bool operator>(const Semver &o) const noexcept
    {
        if (major != o.major) return major > o.major;
        if (minor != o.minor) return minor > o.minor;
        return patch > o.patch;
    }
    bool operator==(const Semver &o) const noexcept
    {
        return major == o.major && minor == o.minor && patch == o.patch;
    }
    bool operator<(const Semver &o) const noexcept  { return o > *this; }
    bool operator>=(const Semver &o) const noexcept { return !(*this < o); }
    bool operator<=(const Semver &o) const noexcept { return !(*this > o); }
    bool operator!=(const Semver &o) const noexcept { return !(*this == o); }

    std::string str() const
    {
        return std::to_string(major) + "."
             + std::to_string(minor) + "."
             + std::to_string(patch);
    }
};

// Parse "MAJOR.MINOR.PATCH".  Sets result.valid = false on any parse error.
inline Semver parseSemver(const std::string &s)
{
    Semver v;
    if (s.empty()) return v;

    // Expect exactly two '.' separators
    auto d1 = s.find('.');
    if (d1 == std::string::npos) return v;
    auto d2 = s.find('.', d1 + 1);
    if (d2 == std::string::npos) return v;
    // No third '.' allowed
    if (s.find('.', d2 + 1) != std::string::npos) return v;

    try
    {
        std::size_t pos = 0;
        unsigned maj = static_cast<unsigned>(std::stoul(s.substr(0, d1), &pos));
        if (pos != d1) return v;
        unsigned min = static_cast<unsigned>(std::stoul(s.substr(d1 + 1, d2 - d1 - 1), &pos));
        if (pos != d2 - d1 - 1) return v;
        unsigned pat = static_cast<unsigned>(std::stoul(s.substr(d2 + 1), &pos));
        if (pos != s.size() - d2 - 1) return v;
        v.major = maj; v.minor = min; v.patch = pat; v.valid = true;
    }
    catch (...) {}
    return v;
}

// ---------------------------------------------------------------------------
// SHA3-256
// ---------------------------------------------------------------------------

// Compute SHA3-256 of [data, data+len).  Returns 32-byte vector; empty on error.
inline std::vector<std::uint8_t> sha3_256(const std::uint8_t *data, std::size_t len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::vector<std::uint8_t> digest(32);
    unsigned int dlen = 32;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) == 1) &&
              (EVP_DigestUpdate(ctx, data, len) == 1) &&
              (EVP_DigestFinal_ex(ctx, digest.data(), &dlen) == 1);
    EVP_MD_CTX_free(ctx);
    if (!ok) return {};
    return digest;
}

// Convenience overload for std::vector<uint8_t>.
inline std::vector<std::uint8_t> sha3_256(const std::vector<std::uint8_t> &v)
{
    return sha3_256(v.data(), v.size());
}

// ---------------------------------------------------------------------------
// Base64 decode (pure C++ — no OpenSSL BIO dependency)
// ---------------------------------------------------------------------------

// Decode standard base64 (with '=' padding).  Returns empty on error.
inline std::vector<std::uint8_t> base64Decode(const std::string &enc)
{
    static const int8_t kTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::vector<std::uint8_t> out;
    out.reserve((enc.size() / 4) * 3);
    int buf = 0, bits = 0;
    for (unsigned char c : enc)
    {
        int v = kTable[c];
        if (v == -2) break;   // '=' padding
        if (v == -1) return {}; // illegal character
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// Hex-decode a string of even length (e.g. nonce from JSON).  Returns empty on error.
inline std::vector<std::uint8_t> hexDecode(const std::string &hex)
{
    if (hex.size() % 2 != 0) return {};
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Hex-encode bytes to lowercase hex string.
inline std::string hexEncode(const std::uint8_t *data, std::size_t len)
{
    static const char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i)
    {
        s.push_back(kHex[(data[i] >> 4) & 0xF]);
        s.push_back(kHex[ data[i]       & 0xF]);
    }
    return s;
}

// ---------------------------------------------------------------------------
// Upgrade auth verification — ML-DSA-65 over (nonce_bytes || binary_sha3)
// ---------------------------------------------------------------------------

// Drain OpenSSL error queue to string.
namespace detail
{
inline std::string opensslErrors()
{
    std::string s;
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error()) != 0)
    {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!s.empty()) s += "; ";
        s += buf;
    }
    return s.empty() ? "(no OpenSSL error)" : s;
}
} // namespace detail

// Verify the ML-DSA-65 auth proof.
// auth_message = nonce_bytes || binary_sha3  (64 bytes total for 32-byte nonce + SHA3-256)
// auth_proof is the ML-DSA-65 signature over auth_message, produced by the push script.
// der_pubkey is the SubjectPublicKeyInfo DER bytes (e.g. kBuildPublicKeyDer).
//
// Returns true if the proof is valid; errOut describes failure.
inline bool verifyUpgradeAuth(
    const std::vector<std::uint8_t> &nonce_bytes,
    const std::vector<std::uint8_t> &binary_sha3,
    const std::vector<std::uint8_t> &auth_proof,
    const std::uint8_t              *der_pubkey,
    std::size_t                      pubkey_len,
    std::string                     &errOut)
{
    if (nonce_bytes.empty() || binary_sha3.empty() || auth_proof.empty())
    {
        errOut = "empty input to verifyUpgradeAuth";
        return false;
    }

    // Concatenate auth_message = nonce_bytes || binary_sha3
    std::vector<std::uint8_t> msg;
    msg.reserve(nonce_bytes.size() + binary_sha3.size());
    msg.insert(msg.end(), nonce_bytes.begin(), nonce_bytes.end());
    msg.insert(msg.end(), binary_sha3.begin(), binary_sha3.end());

    // Load public key from DER
    const std::uint8_t *p = der_pubkey;
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubkey_len));
    if (!pkey)
    {
        errOut = "failed to load upgrade auth public key: " + detail::opensslErrors();
        return false;
    }

    // Verify ML-DSA-65 (md=NULL — algorithm handles hashing internally)
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); errOut = "EVP_MD_CTX_new failed"; return false; }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1)
    {
        errOut = "EVP_DigestVerifyInit failed: " + detail::opensslErrors();
    }
    else
    {
        int rc = EVP_DigestVerify(ctx,
                                  auth_proof.data(), auth_proof.size(),
                                  msg.data(),        msg.size());
        if (rc == 1) ok = true;
        else errOut = "auth proof verification failed: " + detail::opensslErrors();
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// NonceStore — thread-safe, single-use, TTL-based nonce store
// ---------------------------------------------------------------------------

class NonceStore
{
public:
    // Generate a cryptographically random 32-byte nonce, store it with the given
    // TTL (seconds), and return it as a 64-character lowercase hex string.
    // Returns empty string on RAND_bytes failure (should never happen).
    std::string generate(int ttl_sec = 300)
    {
        std::uint8_t raw[32];
        if (RAND_bytes(raw, sizeof(raw)) != 1) return {};
        std::string hex = hexEncode(raw, sizeof(raw));
        const auto expiry = std::chrono::steady_clock::now()
                          + std::chrono::seconds(ttl_sec);
        std::lock_guard<std::mutex> lk(mtx_);
        purgeExpiredLocked();
        nonces_[hex] = Entry{expiry, false};
        return hex;
    }

    // Consume a nonce: returns true if the hex nonce exists, is not expired,
    // and has not been used before.  On success the nonce is marked spent so
    // it cannot be reused (replay attack prevention).
    bool consume(const std::string &hex_nonce)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        purgeExpiredLocked();
        auto it = nonces_.find(hex_nonce);
        if (it == nonces_.end()) return false;               // unknown nonce
        if (std::chrono::steady_clock::now() >= it->second.expiry) return false; // expired
        if (it->second.spent) return false;                  // replay
        it->second.spent = true;
        return true;
    }

    // Inject a known nonce for unit tests (bypasses RAND_bytes).
    void injectForTest(const std::string &hex_nonce, int ttl_sec = 300)
    {
        const auto expiry = std::chrono::steady_clock::now()
                          + std::chrono::seconds(ttl_sec);
        std::lock_guard<std::mutex> lk(mtx_);
        nonces_[hex_nonce] = Entry{expiry, false};
    }

    // Inject an already-expired nonce for unit tests.
    void injectExpiredForTest(const std::string &hex_nonce)
    {
        const auto expiry = std::chrono::steady_clock::now()
                          - std::chrono::seconds(1); // already past
        std::lock_guard<std::mutex> lk(mtx_);
        nonces_[hex_nonce] = Entry{expiry, false};
    }

private:
    struct Entry
    {
        std::chrono::steady_clock::time_point expiry;
        bool spent{false};
    };

    std::mutex mtx_;
    std::unordered_map<std::string, Entry> nonces_;

    // Must be called with mtx_ held.
    void purgeExpiredLocked()
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = nonces_.begin(); it != nonces_.end(); )
        {
            if (now >= it->second.expiry)
                it = nonces_.erase(it);
            else
                ++it;
        }
    }
};

// ---------------------------------------------------------------------------
// Atomic binary + signature replacement
// ---------------------------------------------------------------------------

// Write new binary and signature atomically to targetBinaryPath (same filename,
// new content).  The caller is responsible for verifying the binary+sig pair
// BEFORE calling this function.
//
// Write order:
//   1. Write <targetBinaryPath>.upgrade_tmp   (new binary bytes)
//   2. Write <targetBinaryPath>.sig.upgrade_tmp (new sig bytes)
//   3. rename .sig.upgrade_tmp → <targetBinaryPath>.sig  (atomic)
//   4. rename .upgrade_tmp     → <targetBinaryPath>      (atomic)
//
// On any failure, temp files are removed and targetBinaryPath is unchanged.
// The binary is made executable (mode 0755) after writing.
//
// Returns true on success; errOut describes failure.
inline bool writeUpgradeAtomically(
    const std::string        &targetBinaryPath,
    const std::uint8_t       *binaryData, std::size_t binaryLen,
    const std::uint8_t       *sigData,    std::size_t sigLen,
    std::string              &errOut)
{
    const std::string binTmp = targetBinaryPath + ".upgrade_tmp";
    const std::string sigPath = targetBinaryPath + ".sig";
    const std::string sigTmp = sigPath + ".upgrade_tmp";

    auto cleanup = [&]()
    {
        std::remove(binTmp.c_str());
        std::remove(sigTmp.c_str());
    };

    // Write binary temp
    {
        std::FILE *f = std::fopen(binTmp.c_str(), "wb");
        if (!f) { errOut = "cannot create " + binTmp; return false; }
        bool ok = (binaryLen == 0) || (std::fwrite(binaryData, 1, binaryLen, f) == binaryLen);
        std::fclose(f);
        if (!ok) { cleanup(); errOut = "write failed: " + binTmp; return false; }
    }

    // Set executable bit on the temp binary
    if (std::system(("chmod 0755 '" + binTmp + "' 2>/dev/null").c_str()) != 0)
    {
        cleanup();
        errOut = "chmod failed on " + binTmp;
        return false;
    }

    // Write sig temp
    {
        std::FILE *f = std::fopen(sigTmp.c_str(), "wb");
        if (!f) { cleanup(); errOut = "cannot create " + sigTmp; return false; }
        bool ok = (sigLen == 0) || (std::fwrite(sigData, 1, sigLen, f) == sigLen);
        std::fclose(f);
        if (!ok) { cleanup(); errOut = "write failed: " + sigTmp; return false; }
    }

    // Atomic rename: sig first, then binary
    if (std::rename(sigTmp.c_str(), sigPath.c_str()) != 0)
    {
        cleanup();
        errOut = "rename failed: " + sigTmp + " → " + sigPath;
        return false;
    }
    if (std::rename(binTmp.c_str(), targetBinaryPath.c_str()) != 0)
    {
        // sig has been replaced but binary hasn't — clean up sig tmp (it's gone),
        // but note the sig is now for the new binary while the binary is still old.
        // This is an extremely unlikely partial failure; log clearly.
        errOut = "CRITICAL: sig renamed but binary rename failed: "
                 + binTmp + " → " + targetBinaryPath
                 + ". Deploy the new binary manually to restore consistency.";
        return false;
    }

    return true;
}

} // namespace ntm::upgrade
