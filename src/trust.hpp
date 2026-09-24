#pragma once
// trust.hpp — two-tier binary trust: root keys → delegation → build key → artifact.
//
// Design: docs/signing-trust-model.md (maintainer rulings recorded on #133).
//
//   root keys (3, compiled in, threshold 2)
//       │ sign
//       ▼
//   delegation document  (strict text, versioned, expiring; names build keys)
//       │ authorises
//       ▼
//   build key (one per platform)  ──signs──►  ntm-server / ntm-client binary
//
// Every artifact's <binary>.sig is a self-contained "NTMSIG 2" bundle carrying
// the delegation, its root signatures, the signing key id and the raw ML-DSA-65
// signature over the whole binary. Grammar (strict — any deviation is rejected):
//
//   NTMSIG 2\n
//   delegation: <base64 of the delegation document>\n
//   root-sig: <root id> <base64 ML-DSA-65 signature over the document>\n  (1..3,
//                                                     root ids strictly ascending)
//   key-id: <id>\n
//   signature: <base64 ML-DSA-65 signature over the binary bytes>\n
//
// Delegation document (the exact bytes the roots sign):
//
//   ntm-delegation 1\n
//   version: <decimal, no leading zeros>\n
//   expires: <YYYY-MM-DDTHH:MM:SSZ>\n
//   key: <id> <platform> ML-DSA-65 <base64 SPKI DER>\n                   (1..8)
//
// Policy (maintainer ruling 2): expiry and the rollback floor gate NEW
// artifacts only (updater, pushes, update_dir). The startup self-check
// verifies the full chain with checkExpiry=false. The rollback floor is the
// delegation version of the running binary's own .sig — no extra state.
//
// Pure logic: no logging, no platform singletons. Tests inject their own
// RootSet via verifyBundleWithRoots().

#include "server_signing.hpp"   // verifySignatureWithKeyBytes, detail::readFile
#include "trust_roots.hpp"      // kTrustRoots (generated from signing/roots/)

#include <atomic>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace ntm::trust
{

inline constexpr std::size_t kMaxBundleBytes     = 64 * 1024;
inline constexpr std::size_t kMaxDelegationBytes = 48 * 1024;
inline constexpr std::size_t kMaxDelegatedKeys   = 8;
inline constexpr std::size_t kMaxRootSigs        = 3;

// ntm-server is built for Linux only.
inline constexpr char kServerPlatform[] = "linux-amd64";

struct RootKey
{
    const char         *id;
    const std::uint8_t *der;
    std::size_t         len;
};

struct RootSet
{
    std::vector<RootKey> keys;
    std::size_t          threshold;
};

struct DelegatedKey
{
    std::string               id;
    std::string               platform;
    std::vector<std::uint8_t> spki;
};

struct Delegation
{
    std::uint64_t             version = 0;
    std::int64_t              expires = 0;   // Unix seconds, UTC
    std::vector<DelegatedKey> keys;
};

struct Policy
{
    bool          checkExpiry = false;
    std::int64_t  now         = 0;           // Unix seconds, UTC
    std::uint64_t minVersion  = 0;           // rollback floor (inclusive)
};

struct Verified
{
    std::uint64_t             delegationVersion = 0;
    std::int64_t              expires           = 0;
    std::string               keyId;
    std::vector<std::uint8_t> keySpki;
};

namespace detail
{

// Strict RFC 4648 base64: length multiple of 4, '=' only as final padding,
// no whitespace, unused pad bits zero (one canonical encoding per value).
inline bool b64Decode(std::string_view in, std::vector<std::uint8_t> &out)
{
    out.clear();
    if (in.empty() || in.size() % 4 != 0) return false;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::size_t pad = 0;
    if (in[in.size() - 1] == '=') ++pad;
    if (in[in.size() - 2] == '=') ++pad;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4)
    {
        const bool last = (i + 4 == in.size());
        int v[4];
        for (int j = 0; j < 4; ++j)
        {
            const char c = in[i + j];
            if (c == '=')
            {
                if (!last || j < 4 - static_cast<int>(pad)) return false;
                v[j] = 0;
            }
            else if ((v[j] = val(c)) < 0) return false;
        }
        const std::uint32_t n = (std::uint32_t(v[0]) << 18) | (std::uint32_t(v[1]) << 12)
                              | (std::uint32_t(v[2]) << 6) | std::uint32_t(v[3]);
        out.push_back(static_cast<std::uint8_t>(n >> 16));
        if (!(last && pad == 2)) out.push_back(static_cast<std::uint8_t>(n >> 8));
        if (!(last && pad >= 1)) out.push_back(static_cast<std::uint8_t>(n));
        if (last && pad == 2 && (n & 0xFFFF) != 0) return false;
        if (last && pad == 1 && (n & 0xFF) != 0) return false;
    }
    return true;
}

// Split into lines. Requires a final '\n', forbids '\r' and NUL, forbids empty lines.
inline bool splitLines(std::string_view s, std::vector<std::string_view> &lines)
{
    lines.clear();
    if (s.empty() || s.back() != '\n') return false;
    std::size_t start = 0;
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        const char c = s[i];
        if (c == '\r' || c == '\0') return false;
        if (c == '\n')
        {
            if (i == start) return false;
            lines.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return true;
}

// Consume "<prefix>" from the front of line; returns the remainder.
inline bool takePrefix(std::string_view line, std::string_view prefix, std::string_view &rest)
{
    if (line.substr(0, prefix.size()) != prefix) return false;
    rest = line.substr(prefix.size());
    return true;
}

// Split on single spaces into exactly n non-empty fields.
inline bool splitFields(std::string_view s, std::size_t n, std::vector<std::string_view> &f)
{
    f.clear();
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i)
    {
        if (i == s.size() || s[i] == ' ')
        {
            if (i == start) return false;
            f.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return f.size() == n;
}

inline bool isId(std::string_view s)
{
    if (s.empty() || s.size() > 32) return false;
    for (char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    return true;
}

inline bool isKnownPlatform(std::string_view p)
{
    return p == "linux-amd64" || p == "windows-amd64";
}

inline bool parseVersion(std::string_view s, std::uint64_t &out)
{
    if (s.empty() || s.size() > 18 || s[0] == '0') return false;   // < 10^18 < 2^63
    out = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9') return false;
        out = out * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return true;
}

// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
inline std::int64_t daysFromCivil(std::int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

// Exactly "YYYY-MM-DDTHH:MM:SSZ".
inline bool parseTime(std::string_view s, std::int64_t &out)
{
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':'
        || s[16] != ':' || s[19] != 'Z')
        return false;
    auto num = [&](std::size_t pos, std::size_t len, unsigned &v) {
        v = 0;
        for (std::size_t i = pos; i < pos + len; ++i)
        {
            if (s[i] < '0' || s[i] > '9') return false;
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
        }
        return true;
    };
    unsigned y, mo, d, h, mi, se;
    if (!num(0, 4, y) || !num(5, 2, mo) || !num(8, 2, d) || !num(11, 2, h)
        || !num(14, 2, mi) || !num(17, 2, se))
        return false;
    static const unsigned kDays[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (y < 2000 || mo < 1 || mo > 12 || d < 1 || d > kDays[mo - 1] || h > 23 || mi > 59
        || se > 59)
        return false;
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (mo == 2 && d == 29 && !leap) return false;
    out = daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

inline bool isMlDsa65Spki(const std::vector<std::uint8_t> &der)
{
    const std::uint8_t *p = der.data();
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!pkey) return false;
    const bool ok = EVP_PKEY_is_a(pkey, "ML-DSA-65") == 1
                 && p == der.data() + der.size();   // no trailing bytes
    EVP_PKEY_free(pkey);
    return ok;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Delegation document
// ---------------------------------------------------------------------------

inline bool parseDelegation(std::string_view doc, Delegation &out, std::string &err)
{
    out = Delegation{};
    if (doc.size() > kMaxDelegationBytes) { err = "delegation too large"; return false; }

    std::vector<std::string_view> lines;
    if (!detail::splitLines(doc, lines)) { err = "delegation: malformed lines"; return false; }
    if (lines.size() < 4 || lines.size() > 3 + kMaxDelegatedKeys)
    {
        err = "delegation: wrong number of lines";
        return false;
    }
    if (lines[0] != "ntm-delegation 1") { err = "delegation: bad header"; return false; }

    std::string_view rest;
    if (!detail::takePrefix(lines[1], "version: ", rest) || !detail::parseVersion(rest, out.version))
    {
        err = "delegation: bad version";
        return false;
    }
    if (!detail::takePrefix(lines[2], "expires: ", rest) || !detail::parseTime(rest, out.expires))
    {
        err = "delegation: bad expires";
        return false;
    }

    std::vector<std::string_view> f;
    for (std::size_t i = 3; i < lines.size(); ++i)
    {
        if (!detail::takePrefix(lines[i], "key: ", rest) || !detail::splitFields(rest, 4, f))
        {
            err = "delegation: bad key line";
            return false;
        }
        DelegatedKey k;
        k.id.assign(f[0]);
        k.platform.assign(f[1]);
        if (!detail::isId(f[0])) { err = "delegation: bad key id"; return false; }
        if (!detail::isKnownPlatform(f[1])) { err = "delegation: unknown platform"; return false; }
        if (f[2] != "ML-DSA-65") { err = "delegation: unsupported algorithm"; return false; }
        if (!detail::b64Decode(f[3], k.spki) || !detail::isMlDsa65Spki(k.spki))
        {
            err = "delegation: key '" + k.id + "' is not an ML-DSA-65 SPKI";
            return false;
        }
        for (const auto &prev : out.keys)
            if (prev.id == k.id) { err = "delegation: duplicate key id"; return false; }
        out.keys.push_back(std::move(k));
    }
    return true;
}

// ---------------------------------------------------------------------------
// NTMSIG 2 bundle
// ---------------------------------------------------------------------------

struct Bundle
{
    std::string                                                  document;
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> rootSigs;
    std::string                                                  keyId;
    std::vector<std::uint8_t>                                    signature;
};

inline bool parseBundle(const std::vector<std::uint8_t> &bytes, Bundle &out, std::string &err)
{
    out = Bundle{};
    if (bytes.size() > kMaxBundleBytes) { err = "signature bundle too large"; return false; }
    const std::string_view s(reinterpret_cast<const char *>(bytes.data()), bytes.size());

    std::vector<std::string_view> lines;
    if (!detail::splitLines(s, lines) || lines.empty() || lines[0] != "NTMSIG 2")
    {
        err = "not an NTMSIG 2 signature bundle (legacy or corrupt .sig)";
        return false;
    }
    if (lines.size() < 5 || lines.size() > 4 + kMaxRootSigs)
    {
        err = "bundle: wrong number of lines";
        return false;
    }

    std::string_view rest;
    std::vector<std::uint8_t> docBytes;
    if (!detail::takePrefix(lines[1], "delegation: ", rest) || !detail::b64Decode(rest, docBytes))
    {
        err = "bundle: bad delegation line";
        return false;
    }
    out.document.assign(docBytes.begin(), docBytes.end());

    std::vector<std::string_view> f;
    const std::size_t nRoot = lines.size() - 4;
    for (std::size_t i = 2; i < 2 + nRoot; ++i)
    {
        std::vector<std::uint8_t> sig;
        if (!detail::takePrefix(lines[i], "root-sig: ", rest) || !detail::splitFields(rest, 2, f)
            || !detail::isId(f[0]) || !detail::b64Decode(f[1], sig))
        {
            err = "bundle: bad root-sig line";
            return false;
        }
        if (!out.rootSigs.empty() && !(out.rootSigs.back().first < f[0]))
        {
            err = "bundle: root-sig ids not strictly ascending";
            return false;
        }
        out.rootSigs.emplace_back(std::string(f[0]), std::move(sig));
    }

    if (!detail::takePrefix(lines[2 + nRoot], "key-id: ", rest) || !detail::isId(rest))
    {
        err = "bundle: bad key-id line";
        return false;
    }
    out.keyId.assign(rest);

    if (!detail::takePrefix(lines[3 + nRoot], "signature: ", rest)
        || !detail::b64Decode(rest, out.signature))
    {
        err = "bundle: bad signature line";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify `binary` against its bundle for `platform`, under `roots` and `policy`.
// Order: root threshold over the document → parse → expiry → rollback floor →
// key lookup + platform scope → binary signature. Any failure rejects.
inline bool verifyBundleWithRoots(const std::vector<std::uint8_t> &binary,
                                  const std::vector<std::uint8_t> &bundleBytes,
                                  std::string_view                  platform,
                                  const RootSet                    &roots,
                                  const Policy                     &policy,
                                  Verified                         &out,
                                  std::string                      &err)
{
    out = Verified{};
    Bundle b;
    if (!parseBundle(bundleBytes, b, err)) return false;

    const std::vector<std::uint8_t> doc(b.document.begin(), b.document.end());
    std::size_t valid = 0;
    for (const auto &[rid, sig] : b.rootSigs)
    {
        for (const auto &rk : roots.keys)
        {
            if (rid != rk.id) continue;
            std::string e;
            if (ntm::signing::verifySignatureWithKeyBytes(doc, sig, rk.der, rk.len, e)) ++valid;
            break;
        }
    }
    if (roots.threshold == 0 || valid < roots.threshold)
    {
        err = "delegation has " + std::to_string(valid) + " valid root signature(s); "
            + std::to_string(roots.threshold) + " required";
        return false;
    }

    Delegation d;
    if (!parseDelegation(b.document, d, err)) return false;

    if (policy.checkExpiry && policy.now >= d.expires)
    {
        err = "delegation v" + std::to_string(d.version) + " has expired";
        return false;
    }
    if (d.version < policy.minVersion)
    {
        err = "delegation v" + std::to_string(d.version) + " is older than v"
            + std::to_string(policy.minVersion) + " (rollback rejected)";
        return false;
    }

    const DelegatedKey *key = nullptr;
    for (const auto &k : d.keys)
        if (k.id == b.keyId) { key = &k; break; }
    if (!key) { err = "key '" + b.keyId + "' is not in the delegation"; return false; }
    if (key->platform != platform)
    {
        err = "key '" + b.keyId + "' is scoped to " + key->platform + ", not "
            + std::string(platform);
        return false;
    }

    std::string e;
    if (!ntm::signing::verifySignatureWithKeyBytes(binary, b.signature, key->spki.data(),
                                                   key->spki.size(), e))
    {
        err = "binary signature: " + e;
        return false;
    }

    out.delegationVersion = d.version;
    out.expires           = d.expires;
    out.keyId             = key->id;
    out.keySpki           = key->spki;
    return true;
}

// ---------------------------------------------------------------------------
// Production entry points — compiled-in roots
// ---------------------------------------------------------------------------

inline const RootSet &productionRoots()
{
    static const RootSet set = [] {
        RootSet s;
        s.threshold = kTrustRootThreshold;
        for (const auto &r : kTrustRoots) s.keys.push_back({r.id, r.der, r.len});
        return s;
    }();
    return set;
}

inline std::int64_t nowUtc() { return static_cast<std::int64_t>(std::time(nullptr)); }

// Delegation version of the running binary's own .sig, set by the startup
// self-check. The rollback floor for everything this process accepts.
inline std::atomic<std::uint64_t> &selfDelegationVersion()
{
    static std::atomic<std::uint64_t> v{0};
    return v;
}

// Policy for accepting a NEW artifact (update, push, update_dir scan).
inline Policy acceptPolicy()
{
    return Policy{true, nowUtc(), selfDelegationVersion().load()};
}

// Policy for the startup self-check: full chain, no expiry, no floor.
inline Policy startupPolicy() { return Policy{false, 0, 0}; }

inline bool verifyArtifactBytes(const std::vector<std::uint8_t> &binary,
                                const std::vector<std::uint8_t> &bundle,
                                std::string_view                  platform,
                                const Policy                     &policy,
                                Verified                         &out,
                                std::string                      &err)
{
    return verifyBundleWithRoots(binary, bundle, platform, productionRoots(), policy, out, err);
}

inline bool verifyArtifactFiles(const std::string &binaryPath,
                                const std::string &sigPath,
                                std::string_view   platform,
                                const Policy      &policy,
                                Verified          &out,
                                std::string       &err)
{
    std::vector<std::uint8_t> bin, sig;
    if (!ntm::signing::detail::readFile(binaryPath, bin, err)) return false;
    if (!ntm::signing::detail::readFile(sigPath, sig, err)) return false;
    return verifyArtifactBytes(bin, sig, platform, policy, out, err);
}

} // namespace ntm::trust
