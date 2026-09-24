// test_trust.cpp — unit tests for src/trust.hpp (two-tier binary trust).
//
// Builds real NTMSIG 2 bundles with throwaway ML-DSA-65 keys (openssl CLI) and
// checks every rejection path: root threshold, unknown/duplicate roots,
// tampered delegation, expiry, rollback floor, platform scope, unknown key id,
// tampered binary, legacy .sig, and the strict text grammar.

#include "trust.hpp"
#include "ntm_test.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace
{

bool shell(const std::string &cmd)
{
#ifdef _WIN32
    return std::system(("\"" + cmd + "\"").c_str()) == 0;
#else
    return std::system(cmd.c_str()) == 0;
#endif
}

#ifdef _WIN32
const std::string kNoStderr = " 2>NUL";
#else
const std::string kNoStderr = " 2>/dev/null";
#endif

std::string quotePath(const std::string &s) { return "\"" + s + "\""; }

std::string tmpPath(const std::string &name)
{
    return (std::filesystem::temp_directory_path() / name).string();
}

const std::string &openssl()
{
    static const std::string cmd = [] {
#ifdef _WIN32
        const char *msys = "C:/msys64/mingw64/bin/openssl.exe";
        if (std::system("where openssl >NUL 2>NUL") != 0 && std::filesystem::exists(msys))
            return quotePath(msys);
#endif
        return std::string("openssl");
    }();
    return cmd;
}

std::vector<std::uint8_t> readVec(const std::string &path)
{
    std::vector<std::uint8_t> v;
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return v;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::rewind(f);
    if (sz > 0)
    {
        v.resize(static_cast<std::size_t>(sz));
        if (std::fread(v.data(), 1, v.size(), f) != v.size()) v.clear();
    }
    std::fclose(f);
    return v;
}

void writeVec(const std::string &path, const std::vector<std::uint8_t> &v)
{
    FILE *f = std::fopen(path.c_str(), "wb");
    if (!f) return;
    if (!v.empty()) std::fwrite(v.data(), 1, v.size(), f);
    std::fclose(f);
}

std::string b64(const std::vector<std::uint8_t> &in)
{
    static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3)
    {
        const unsigned n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out += t[(n >> 18) & 63]; out += t[(n >> 12) & 63]; out += t[(n >> 6) & 63]; out += t[n & 63];
    }
    if (i + 1 == in.size())
    {
        const unsigned n = in[i] << 16;
        out += t[(n >> 18) & 63]; out += t[(n >> 12) & 63]; out += "==";
    }
    else if (i + 2 == in.size())
    {
        const unsigned n = (in[i] << 16) | (in[i + 1] << 8);
        out += t[(n >> 18) & 63]; out += t[(n >> 12) & 63]; out += t[(n >> 6) & 63]; out += '=';
    }
    return out;
}

std::vector<std::uint8_t> bytes(const std::string &s) { return {s.begin(), s.end()}; }

struct TestKey
{
    std::string               priv;
    std::vector<std::uint8_t> spki;
};

static int g_trustKeyIdx = 0;
TestKey makeKey()
{
    TestKey k;
    const int idx = g_trustKeyIdx++;
    k.priv = tmpPath("ntm_test_trust_priv_" + std::to_string(idx) + ".pem");
    const std::string pub = tmpPath("ntm_test_trust_pub_" + std::to_string(idx) + ".der");
    if (shell(openssl() + " genpkey -algorithm ML-DSA-65 -out " + quotePath(k.priv) + kNoStderr)
        && shell(openssl() + " pkey -in " + quotePath(k.priv) + " -pubout -outform DER -out "
                 + quotePath(pub) + kNoStderr))
        k.spki = readVec(pub);
    return k;
}

std::vector<std::uint8_t> sign(const TestKey &k, const std::vector<std::uint8_t> &msg)
{
    const std::string in  = tmpPath("ntm_test_trust_msg.bin");
    const std::string out = tmpPath("ntm_test_trust_sig.bin");
    writeVec(in, msg);
    std::remove(out.c_str());
    shell(openssl() + " pkeyutl -sign -rawin -inkey " + quotePath(k.priv) + " -in " + quotePath(in)
          + " -out " + quotePath(out) + kNoStderr);
    return readVec(out);
}

struct Fix
{
    TestKey r1, r2, r3, linuxKey, winKey;
    ntm::trust::RootSet roots;
    std::vector<std::uint8_t> binary = bytes("pretend this is an ntm-client binary\x01\x02");
    bool ok = false;

    Fix()
    {
        r1 = makeKey(); r2 = makeKey(); r3 = makeKey(); linuxKey = makeKey(); winKey = makeKey();
        ok = !r1.spki.empty() && !r2.spki.empty() && !r3.spki.empty() && !linuxKey.spki.empty()
          && !winKey.spki.empty();
        roots.threshold = 2;
        roots.keys = {{"r1", r1.spki.data(), r1.spki.size()},
                      {"r2", r2.spki.data(), r2.spki.size()},
                      {"r3", r3.spki.data(), r3.spki.size()}};
    }

    std::string doc(std::uint64_t version = 7, const std::string &expires = "2099-01-01T00:00:00Z")
    {
        return "ntm-delegation 1\nversion: " + std::to_string(version) + "\nexpires: " + expires
             + "\nkey: linux-build linux-amd64 ML-DSA-65 " + b64(linuxKey.spki)
             + "\nkey: windows-build windows-amd64 ML-DSA-65 " + b64(winKey.spki) + "\n";
    }

    // Assemble a bundle. `signers` pairs a root id with the key that signs the
    // document under that id (lets tests forge mismatches).
    std::vector<std::uint8_t> bundle(const std::string &document,
                                     const std::vector<std::pair<std::string, const TestKey *>> &signers,
                                     const std::string &keyId, const TestKey &buildKey,
                                     const std::vector<std::uint8_t> *bin = nullptr)
    {
        std::string s = "NTMSIG 2\ndelegation: " + b64(bytes(document)) + "\n";
        for (const auto &[id, k] : signers) s += "root-sig: " + id + " " + b64(sign(*k, bytes(document))) + "\n";
        s += "key-id: " + keyId + "\nsignature: " + b64(sign(buildKey, bin ? *bin : binary)) + "\n";
        return bytes(s);
    }

    std::vector<std::uint8_t> good(const std::string &document)
    {
        return bundle(document, {{"r1", &r1}, {"r2", &r2}}, "linux-build", linuxKey);
    }
};

Fix &fx()
{
    static Fix f;
    return f;
}

bool verify(const std::vector<std::uint8_t> &bin, const std::vector<std::uint8_t> &b,
            const std::string &platform, const ntm::trust::Policy &pol, std::string &err,
            ntm::trust::Verified *outp = nullptr)
{
    ntm::trust::Verified v;
    const bool ok = ntm::trust::verifyBundleWithRoots(bin, b, platform, fx().roots, pol, v, err);
    if (outp) *outp = v;
    return ok;
}

} // namespace

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

TEST_CASE("trust: valid bundle with 2 of 3 roots verifies")
{
    REQUIRE(fx().ok);
    std::string err;
    ntm::trust::Verified v;
    REQUIRE(verify(fx().binary, fx().good(fx().doc()), "linux-amd64", {}, err, &v));
    REQUIRE_EQ(v.delegationVersion, std::uint64_t{7});
    REQUIRE(v.keyId == "linux-build");
    REQUIRE(v.keySpki == fx().linuxKey.spki);
}

TEST_CASE("trust: all three roots, and the r2+r3 pair, verify")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r2", &f.r2}, {"r3", &f.r3}}, "linux-build", f.linuxKey),
                   "linux-amd64", {}, err));
    REQUIRE(verify(f.binary, f.bundle(f.doc(), {{"r2", &f.r2}, {"r3", &f.r3}}, "linux-build", f.linuxKey),
                   "linux-amd64", {}, err));
}

TEST_CASE("trust: windows key verifies a windows artifact")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r3", &f.r3}}, "windows-build", f.winKey),
                   "windows-amd64", {}, err));
}

// ---------------------------------------------------------------------------
// Root threshold
// ---------------------------------------------------------------------------

TEST_CASE("trust: one root signature is below threshold")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}}, "linux-build", f.linuxKey), "linux-amd64", {}, err));
    REQUIRE(err.find("1 valid root") != std::string::npos);
}

TEST_CASE("trust: repeated root id is rejected, not double-counted")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r1", &f.r1}}, "linux-build", f.linuxKey),
                    "linux-amd64", {}, err));
}

TEST_CASE("trust: unknown root id does not count")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r9", &f.r2}}, "linux-build", f.linuxKey),
                    "linux-amd64", {}, err));
}

TEST_CASE("trust: a non-root key claiming a root id does not count")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    // linuxKey signs under the name "r2": the r2 slot fails, leaving 1 valid.
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r2", &f.linuxKey}}, "linux-build", f.linuxKey),
                    "linux-amd64", {}, err));
}

TEST_CASE("trust: roots signed a different document than the one bundled")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    auto b = f.good(f.doc(7));
    // Swap in a version-8 document while keeping the v7 root signatures.
    std::string s(b.begin(), b.end());
    const std::string oldLine = "delegation: " + b64(bytes(f.doc(7)));
    s.replace(s.find(oldLine), oldLine.size(), "delegation: " + b64(bytes(f.doc(8))));
    std::string err;
    REQUIRE(!verify(f.binary, bytes(s), "linux-amd64", {}, err));
}

// ---------------------------------------------------------------------------
// Policy: expiry and rollback
// ---------------------------------------------------------------------------

TEST_CASE("trust: expiry is enforced only when policy asks")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    auto b = f.good(f.doc(7, "2020-01-01T00:00:00Z"));
    std::string err;
    ntm::trust::Policy accept{true, 1900000000, 0};
    REQUIRE(!verify(f.binary, b, "linux-amd64", accept, err));
    REQUIRE(err.find("expired") != std::string::npos);
    ntm::trust::Policy startup{false, 1900000000, 0};
    REQUIRE(verify(f.binary, b, "linux-amd64", startup, err));
}

TEST_CASE("trust: expiry boundary — valid until the second before")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    auto b = f.good(f.doc(7, "2027-04-23T00:00:00Z"));   // 1808438400
    std::string err;
    REQUIRE(verify(f.binary, b, "linux-amd64", {true, 1808438399, 0}, err));
    REQUIRE(!verify(f.binary, b, "linux-amd64", {true, 1808438400, 0}, err));
}

TEST_CASE("trust: rollback floor is inclusive")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    auto b = f.good(f.doc(7));
    std::string err;
    REQUIRE(verify(f.binary, b, "linux-amd64", {false, 0, 7}, err));
    REQUIRE(!verify(f.binary, b, "linux-amd64", {false, 0, 8}, err));
    REQUIRE(err.find("rollback") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Key selection and the artifact signature
// ---------------------------------------------------------------------------

TEST_CASE("trust: key is scoped to its platform")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, f.good(f.doc()), "windows-amd64", {}, err));
    REQUIRE(err.find("scoped") != std::string::npos);
}

TEST_CASE("trust: key id absent from the delegation")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r2", &f.r2}}, "mac-build", f.linuxKey),
                    "linux-amd64", {}, err));
}

TEST_CASE("trust: binary signed by the wrong delegated key")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    // Claims linux-build but is signed with the windows key.
    REQUIRE(!verify(f.binary, f.bundle(f.doc(), {{"r1", &f.r1}, {"r2", &f.r2}}, "linux-build", f.winKey),
                    "linux-amd64", {}, err));
}

TEST_CASE("trust: tampered binary")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    auto bin = f.binary;
    bin[0] ^= 1;
    std::string err;
    REQUIRE(!verify(bin, f.good(f.doc()), "linux-amd64", {}, err));
}

TEST_CASE("trust: legacy raw .sig is rejected with a clear message")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    std::string err;
    REQUIRE(!verify(f.binary, sign(f.linuxKey, f.binary), "linux-amd64", {}, err));
    REQUIRE(err.find("NTMSIG 2") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Grammar strictness
// ---------------------------------------------------------------------------

TEST_CASE("trust: bundle grammar rejects CRLF, trailing data, missing newline")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    const auto good = f.good(f.doc());
    std::string s(good.begin(), good.end()), err;
    ntm::trust::Bundle b;
    REQUIRE(ntm::trust::parseBundle(good, b, err));

    std::string crlf = s;
    crlf.insert(crlf.find('\n'), "\r");
    REQUIRE(!ntm::trust::parseBundle(bytes(crlf), b, err));
    REQUIRE(!ntm::trust::parseBundle(bytes(s + "extra: 1\n"), b, err));
    REQUIRE(!ntm::trust::parseBundle(bytes(s.substr(0, s.size() - 1)), b, err));
    REQUIRE(!ntm::trust::parseBundle(bytes("NTMSIG 3" + s.substr(8)), b, err));
}

TEST_CASE("trust: delegation grammar")
{
    REQUIRE(fx().ok);
    auto &f = fx();
    ntm::trust::Delegation d;
    std::string err;
    const std::string good = f.doc(12, "2027-04-23T00:00:00Z");
    REQUIRE(ntm::trust::parseDelegation(good, d, err));
    REQUIRE_EQ(d.version, std::uint64_t{12});
    REQUIRE_EQ(d.expires, std::int64_t{1808438400});
    REQUIRE_EQ(d.keys.size(), std::size_t{2});

    auto mut = [&](const std::string &from, const std::string &to) {
        std::string s = good;
        s.replace(s.find(from), from.size(), to);
        return s;
    };
    REQUIRE(!ntm::trust::parseDelegation(mut("version: 12", "version: 012"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut("version: 12", "version:  12"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut("2027-04-23", "2027-02-30"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut("2027-04-23", "2027-02-29"), d, err));   // not leap
    REQUIRE(!ntm::trust::parseDelegation(mut("T00:00:00Z", "T00:00:00+01:00"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut("linux-amd64", "linux-arm64"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut(" ML-DSA-65 ", " ML-DSA-87 "), d, err));
    REQUIRE(!ntm::trust::parseDelegation(mut("windows-build ", "linux-build "), d, err));   // dup id
    REQUIRE(!ntm::trust::parseDelegation(mut("ntm-delegation 1", "ntm-delegation 2"), d, err));
    REQUIRE(!ntm::trust::parseDelegation(good + "\n", d, err));                              // empty line
    REQUIRE(!ntm::trust::parseDelegation(mut("linux-build linux", "Linux-build linux"), d, err));

    std::string leap = mut("2027-04-23", "2028-02-29");
    REQUIRE(ntm::trust::parseDelegation(leap, d, err));
}

TEST_CASE("trust: strict base64")
{
    std::vector<std::uint8_t> out;
    REQUIRE(ntm::trust::detail::b64Decode("Zm9v", out));
    REQUIRE(out == bytes("foo"));
    REQUIRE(ntm::trust::detail::b64Decode("Zg==", out));
    REQUIRE(out == bytes("f"));
    REQUIRE(ntm::trust::detail::b64Decode("Zm8=", out));
    REQUIRE(out == bytes("fo"));
    REQUIRE(!ntm::trust::detail::b64Decode("", out));
    REQUIRE(!ntm::trust::detail::b64Decode("Zm9", out));      // length
    REQUIRE(!ntm::trust::detail::b64Decode("Zh==", out));     // non-zero pad bits
    REQUIRE(!ntm::trust::detail::b64Decode("Zm9v\n", out));   // whitespace
    REQUIRE(!ntm::trust::detail::b64Decode("Z=9v", out));     // '=' mid-quad
    REQUIRE(!ntm::trust::detail::b64Decode("Zg==Zm9v", out)); // '=' before the end
    REQUIRE(!ntm::trust::detail::b64Decode("Zm-v", out));     // url-safe alphabet
}

TEST_CASE("trust: oversized bundle rejected before parsing")
{
    std::vector<std::uint8_t> big(ntm::trust::kMaxBundleBytes + 1, 'A');
    ntm::trust::Bundle b;
    std::string err;
    REQUIRE(!ntm::trust::parseBundle(big, b, err));
    REQUIRE(err.find("too large") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Production roots
// ---------------------------------------------------------------------------

TEST_CASE("trust: compiled-in roots are three distinct ML-DSA-65 keys, threshold 2")
{
    const auto &r = ntm::trust::productionRoots();
    REQUIRE_EQ(r.keys.size(), std::size_t{3});
    REQUIRE_EQ(r.threshold, std::size_t{2});
    for (std::size_t i = 0; i < r.keys.size(); ++i)
    {
        std::vector<std::uint8_t> der(r.keys[i].der, r.keys[i].der + r.keys[i].len);
        REQUIRE(ntm::trust::detail::isMlDsa65Spki(der));
        for (std::size_t j = 0; j < i; ++j)
            REQUIRE(!(r.keys[j].len == r.keys[i].len
                      && std::equal(r.keys[j].der, r.keys[j].der + r.keys[j].len, r.keys[i].der)));
    }
}
