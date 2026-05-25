// test_server_upgrade.cpp — unit tests for src/server_upgrade.hpp
//
// Tests (all pure logic, no live server):
//   parseSemver       — valid, invalid, edge cases
//   Semver comparison — all six operators
//   sha3_256          — known test vector
//   base64Decode      — RFC 4648 vectors
//   hexDecode/Encode  — round-trip
//   verifyUpgradeAuth — valid proof, wrong key, tampered nonce, tampered hash
//   NonceStore        — generate+consume, double-spend, expired, unknown
//   writeUpgradeAtomically — atomic replacement, leaves target unchanged on failure

#include "server_upgrade.hpp"
#include "ntm_test.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace
{

bool shell(const std::string &cmd) { return std::system(cmd.c_str()) == 0; }

std::string writeTmp(const std::string &suffix, const std::string &content)
{
    std::string path = "/tmp/ntm_test_upgrade_" + suffix;
    std::FILE *f = std::fopen(path.c_str(), "wb");
    if (f)
    {
        if (!content.empty())
            std::fwrite(content.data(), 1, content.size(), f);
        std::fclose(f);
    }
    return path;
}

std::string readFile(const std::string &path)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return "";
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f); std::rewind(f);
    std::string s(static_cast<std::size_t>(sz < 0 ? 0 : sz), '\0');
    if (sz > 0) std::fread(s.data(), 1, static_cast<std::size_t>(sz), f);
    std::fclose(f);
    return s;
}

// Generate a test ML-DSA-65 key pair.  Returns private key path and DER public key.
bool makeTmpKeyPair(std::string &privPath, std::vector<std::uint8_t> &pubDer)
{
    privPath = "/tmp/ntm_test_upgrade_priv.pem";
    std::string pubDerPath = "/tmp/ntm_test_upgrade_pub.der";
    if (!shell("openssl genpkey -algorithm ML-DSA-65 -out " + privPath + " 2>/dev/null")) return false;
    if (!shell("openssl pkey -in " + privPath
               + " -pubout -outform DER -out " + pubDerPath + " 2>/dev/null")) return false;
    std::string raw = readFile(pubDerPath);
    pubDer.assign(raw.begin(), raw.end());
    return !pubDer.empty();
}

// Sign auth_message with private key, return ML-DSA-65 sig bytes.
std::vector<std::uint8_t> signBytes(const std::string &privPath,
                                    const std::vector<std::uint8_t> &msg)
{
    std::string msgPath = "/tmp/ntm_test_upgrade_auth_msg.bin";
    std::string sigPath = "/tmp/ntm_test_upgrade_auth_proof.bin";
    std::FILE *f = std::fopen(msgPath.c_str(), "wb");
    if (f) { std::fwrite(msg.data(), 1, msg.size(), f); std::fclose(f); }
    shell("openssl pkeyutl -sign -inkey " + privPath
          + " -in " + msgPath + " -out " + sigPath + " 2>/dev/null");
    std::string raw = readFile(sigPath);
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

// Build a valid auth proof: sign (nonce_bytes || sha3_256(binary))
std::vector<std::uint8_t> makeAuthProof(const std::string &privPath,
                                         const std::vector<std::uint8_t> &nonce,
                                         const std::vector<std::uint8_t> &binary)
{
    auto hash = ntm::upgrade::sha3_256(binary);
    std::vector<std::uint8_t> msg;
    msg.insert(msg.end(), nonce.begin(), nonce.end());
    msg.insert(msg.end(), hash.begin(),  hash.end());
    return signBytes(privPath, msg);
}

// ── Shared key fixture ────────────────────────────────────────────────────────
struct KeyFix
{
    std::string priv;
    std::vector<std::uint8_t> pub;
    bool ok = false;
    KeyFix() { ok = makeTmpKeyPair(priv, pub); }
};
static KeyFix g_kf;

} // namespace

// ---------------------------------------------------------------------------
// parseSemver
// ---------------------------------------------------------------------------

TEST_CASE("parseSemver: valid version strings")
{
    auto v = ntm::upgrade::parseSemver("1.17.0");
    REQUIRE(v.valid);
    REQUIRE_EQ(v.major, 1u); REQUIRE_EQ(v.minor, 17u); REQUIRE_EQ(v.patch, 0u);

    auto v2 = ntm::upgrade::parseSemver("0.0.1");
    REQUIRE(v2.valid);
    REQUIRE_EQ(v2.patch, 1u);

    auto v3 = ntm::upgrade::parseSemver("10.200.300");
    REQUIRE(v3.valid);
    REQUIRE_EQ(v3.major, 10u); REQUIRE_EQ(v3.minor, 200u); REQUIRE_EQ(v3.patch, 300u);
}

TEST_CASE("parseSemver: invalid version strings")
{
    REQUIRE(!ntm::upgrade::parseSemver("").valid);
    REQUIRE(!ntm::upgrade::parseSemver("1").valid);
    REQUIRE(!ntm::upgrade::parseSemver("1.2").valid);
    REQUIRE(!ntm::upgrade::parseSemver("a.b.c").valid);
    REQUIRE(!ntm::upgrade::parseSemver("1.2.").valid);
    REQUIRE(!ntm::upgrade::parseSemver(".1.2").valid);
    REQUIRE(!ntm::upgrade::parseSemver("1.2.3.4.5").valid);
}

TEST_CASE("parseSemver: 4-part version strings")
{
    auto v = ntm::upgrade::parseSemver("1.18.0.0");
    REQUIRE(v.valid);
    REQUIRE_EQ(v.major, 1u);
    REQUIRE_EQ(v.minor, 18u);
    REQUIRE_EQ(v.patch, 0u);
    REQUIRE_EQ(v.revision, 0u);

    auto v2 = ntm::upgrade::parseSemver("2.0.0.1");
    REQUIRE(v2.valid);
    REQUIRE_EQ(v2.revision, 1u);

    // 3-part still valid (revision = 0)
    auto v3 = ntm::upgrade::parseSemver("1.17.0");
    REQUIRE(v3.valid);
    REQUIRE_EQ(v3.revision, 0u);

    // 5-part invalid
    REQUIRE(!ntm::upgrade::parseSemver("1.2.3.4.5").valid);
}

TEST_CASE("Semver: 4-part comparison operators")
{
    using ntm::upgrade::parseSemver;
    auto v1000 = parseSemver("1.0.0.0");
    auto v1001 = parseSemver("1.0.0.1");
    auto v1010 = parseSemver("1.0.1.0");

    REQUIRE(v1000 < v1001);
    REQUIRE(v1001 < v1010);
    REQUIRE(v1010 > v1001);
    REQUIRE(v1000 == parseSemver("1.0.0.0"));
    REQUIRE(v1001 != v1000);

    // 3-part "1.0.0" equals 4-part "1.0.0.0"
    REQUIRE(parseSemver("1.0.0") == parseSemver("1.0.0.0"));
}

TEST_CASE("Semver::str returns 4-part string")
{
    auto v = ntm::upgrade::parseSemver("1.18.0.0");
    REQUIRE_EQ(v.str(), std::string("1.18.0.0"));

    auto v2 = ntm::upgrade::parseSemver("1.17.0");
    REQUIRE_EQ(v2.str(), std::string("1.17.0.0")); // 3-part gets .0 appended
}

// ---------------------------------------------------------------------------
// Semver comparison
// ---------------------------------------------------------------------------

TEST_CASE("Semver: comparison operators")
{
    using ntm::upgrade::parseSemver;
    auto v100 = parseSemver("1.0.0");
    auto v110 = parseSemver("1.1.0");
    auto v111 = parseSemver("1.1.1");
    auto v200 = parseSemver("2.0.0");
    auto v100b = parseSemver("1.0.0");

    REQUIRE(v100 < v110);
    REQUIRE(v110 < v111);
    REQUIRE(v111 < v200);
    REQUIRE(v200 > v111);
    REQUIRE(v100 == v100b);
    REQUIRE(v100 != v110);
    REQUIRE(v110 >= v100);
    REQUIRE(v100 <= v110);
    REQUIRE(!(v100 > v110));
    REQUIRE(!(v200 < v111));
}

TEST_CASE("Semver: str() round-trip")
{
    auto v = ntm::upgrade::parseSemver("1.17.3");
    REQUIRE_EQ(v.str(), std::string("1.17.3.0")); // 3-part input → 4-part output (revision=0)
}

// ---------------------------------------------------------------------------
// sha3_256
// ---------------------------------------------------------------------------

TEST_CASE("sha3_256: known test vector for empty input")
{
    // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    std::vector<std::uint8_t> h = ntm::upgrade::sha3_256(nullptr, 0);
    // Can't pass nullptr to sha3_256 overload that takes pointer; use empty vector
    std::vector<std::uint8_t> empty;
    h = ntm::upgrade::sha3_256(empty);
    REQUIRE_EQ(h.size(), std::size_t(32));
    REQUIRE_EQ(ntm::upgrade::hexEncode(h.data(), h.size()),
               std::string("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
}

TEST_CASE("sha3_256: known test vector for 'abc'")
{
    // SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    const std::uint8_t abc[] = {'a', 'b', 'c'};
    auto h = ntm::upgrade::sha3_256(abc, 3);
    REQUIRE_EQ(h.size(), std::size_t(32));
    REQUIRE_EQ(ntm::upgrade::hexEncode(h.data(), h.size()),
               std::string("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
}

TEST_CASE("sha3_256: different inputs produce different hashes")
{
    const std::uint8_t a[] = {'a'};
    const std::uint8_t b[] = {'b'};
    auto ha = ntm::upgrade::sha3_256(a, 1);
    auto hb = ntm::upgrade::sha3_256(b, 1);
    REQUIRE(ha != hb);
}

// ---------------------------------------------------------------------------
// base64Decode
// ---------------------------------------------------------------------------

TEST_CASE("base64Decode: RFC 4648 test vectors")
{
    // "" → ""
    REQUIRE(ntm::upgrade::base64Decode("").empty());
    // "Zg==" → "f"
    auto r1 = ntm::upgrade::base64Decode("Zg==");
    REQUIRE_EQ(r1.size(), std::size_t(1));
    REQUIRE_EQ(r1[0], std::uint8_t('f'));
    // "Zm8=" → "fo"
    auto r2 = ntm::upgrade::base64Decode("Zm8=");
    REQUIRE_EQ(r2.size(), std::size_t(2));
    REQUIRE_EQ(r2[0], std::uint8_t('f')); REQUIRE_EQ(r2[1], std::uint8_t('o'));
    // "Zm9v" → "foo"
    auto r3 = ntm::upgrade::base64Decode("Zm9v");
    REQUIRE_EQ(r3.size(), std::size_t(3));
    REQUIRE_EQ(std::string(r3.begin(), r3.end()), std::string("foo"));
}

TEST_CASE("base64Decode: invalid character returns empty")
{
    auto r = ntm::upgrade::base64Decode("Zm9!"); // '!' is invalid
    REQUIRE(r.empty());
}

// ---------------------------------------------------------------------------
// hexDecode / hexEncode
// ---------------------------------------------------------------------------

TEST_CASE("hexDecode/hexEncode: round-trip")
{
    const std::uint8_t data[] = {0x00, 0xFF, 0xAB, 0x12};
    std::string hex = ntm::upgrade::hexEncode(data, 4);
    REQUIRE_EQ(hex, std::string("00ffab12"));
    auto back = ntm::upgrade::hexDecode(hex);
    REQUIRE_EQ(back.size(), std::size_t(4));
    REQUIRE(std::memcmp(back.data(), data, 4) == 0);
}

TEST_CASE("hexDecode: odd-length input returns empty")
{
    REQUIRE(ntm::upgrade::hexDecode("abc").empty());
}

TEST_CASE("hexDecode: invalid hex character returns empty")
{
    REQUIRE(ntm::upgrade::hexDecode("zz").empty());
}

// ---------------------------------------------------------------------------
// verifyUpgradeAuth
// ---------------------------------------------------------------------------

TEST_CASE("verifyUpgradeAuth: valid proof verifies")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> nonce(32, 0xAA);
    const std::vector<std::uint8_t> binary = {'h','e','l','l','o'};
    auto proof = makeAuthProof(g_kf.priv, nonce, binary);
    REQUIRE(!proof.empty());

    auto hash = ntm::upgrade::sha3_256(binary);
    std::string err;
    REQUIRE(ntm::upgrade::verifyUpgradeAuth(nonce, hash, proof,
                                            g_kf.pub.data(), g_kf.pub.size(), err));
}

TEST_CASE("verifyUpgradeAuth: wrong public key → fails")
{
    REQUIRE(g_kf.ok);
    // Generate a second key pair with a DIFFERENT file path to avoid
    // overwriting the shared fixture key used by g_kf.priv.
    std::string priv2 = "/tmp/ntm_test_upgrade_priv2.pem";
    std::string pub2Der = "/tmp/ntm_test_upgrade_pub2.der";
    REQUIRE(shell("openssl genpkey -algorithm ML-DSA-65 -out " + priv2 + " 2>/dev/null"));
    REQUIRE(shell("openssl pkey -in " + priv2
                  + " -pubout -outform DER -out " + pub2Der + " 2>/dev/null"));
    std::string raw = readFile(pub2Der);
    std::vector<std::uint8_t> pub2(raw.begin(), raw.end());
    REQUIRE(!pub2.empty());

    const std::vector<std::uint8_t> nonce(32, 0xBB);
    const std::vector<std::uint8_t> binary = {'t','e','s','t'};
    auto proof = makeAuthProof(g_kf.priv, nonce, binary);
    auto hash  = ntm::upgrade::sha3_256(binary);

    std::string err;
    // Verify with different key — must fail
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth(nonce, hash, proof,
                                              pub2.data(), pub2.size(), err));
}

TEST_CASE("verifyUpgradeAuth: tampered nonce → fails")
{
    REQUIRE(g_kf.ok);
    std::vector<std::uint8_t> nonce(32, 0xCC);
    const std::vector<std::uint8_t> binary = {'d','a','t','a'};
    auto proof = makeAuthProof(g_kf.priv, nonce, binary);
    auto hash  = ntm::upgrade::sha3_256(binary);

    // Flip one byte in the nonce
    nonce[0] ^= 0xFF;
    std::string err;
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth(nonce, hash, proof,
                                              g_kf.pub.data(), g_kf.pub.size(), err));
}

TEST_CASE("verifyUpgradeAuth: tampered binary hash → fails")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> nonce(32, 0xDD);
    const std::vector<std::uint8_t> binary = {'b','i','n'};
    auto proof = makeAuthProof(g_kf.priv, nonce, binary);
    auto hash  = ntm::upgrade::sha3_256(binary);

    // Flip one byte in the hash
    hash[15] ^= 0xFF;
    std::string err;
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth(nonce, hash, proof,
                                              g_kf.pub.data(), g_kf.pub.size(), err));
}

TEST_CASE("verifyUpgradeAuth: empty inputs → fails with error")
{
    REQUIRE(g_kf.ok);
    std::string err;
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth({}, {}, {},
                                              g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(!err.empty());
}

// ---------------------------------------------------------------------------
// NonceStore
// ---------------------------------------------------------------------------

TEST_CASE("NonceStore: generate returns 64-char hex nonce")
{
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate();
    REQUIRE_EQ(nonce.size(), std::size_t(64)); // 32 bytes → 64 hex chars
    // All chars must be valid hex
    for (char c : nonce)
        REQUIRE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

TEST_CASE("NonceStore: generated nonce can be consumed once")
{
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate();
    REQUIRE(store.consume(nonce));
}

TEST_CASE("NonceStore: nonce cannot be consumed twice (replay prevention)")
{
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate();
    REQUIRE(store.consume(nonce));
    REQUIRE(!store.consume(nonce)); // second use must fail
}

TEST_CASE("NonceStore: unknown nonce → consume returns false")
{
    ntm::upgrade::NonceStore store;
    REQUIRE(!store.consume("0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST_CASE("NonceStore: expired nonce → consume returns false")
{
    ntm::upgrade::NonceStore store;
    const std::string nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
    store.injectExpiredForTest(nonce);
    REQUIRE(!store.consume(nonce));
}

TEST_CASE("NonceStore: injected test nonce can be consumed once")
{
    ntm::upgrade::NonceStore store;
    const std::string nonce = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    store.injectForTest(nonce, 300);
    REQUIRE(store.consume(nonce));
    REQUIRE(!store.consume(nonce)); // replay
}

TEST_CASE("NonceStore: two different nonces are independent")
{
    ntm::upgrade::NonceStore store;
    std::string n1 = store.generate();
    std::string n2 = store.generate();
    REQUIRE(n1 != n2);
    REQUIRE(store.consume(n1));
    REQUIRE(store.consume(n2));
}

// ---------------------------------------------------------------------------
// writeUpgradeAtomically
// ---------------------------------------------------------------------------

TEST_CASE("writeUpgradeAtomically: replaces target file with new content")
{
    // Create a "current binary" at a temp path
    std::string target = "/tmp/ntm_test_upgrade_atomic_bin";
    std::string sigPath = target + ".sig";
    // Seed with old content
    writeTmp("atomic_bin",     "OLD BINARY CONTENT");
    writeTmp("atomic_bin.sig", "OLD SIG CONTENT");

    const std::string newBin = "NEW BINARY CONTENT v1.18.0";
    const std::string newSig = "NEW SIG CONTENT";

    std::string err;
    bool ok = ntm::upgrade::writeUpgradeAtomically(
        target,
        reinterpret_cast<const std::uint8_t *>(newBin.data()), newBin.size(),
        reinterpret_cast<const std::uint8_t *>(newSig.data()), newSig.size(),
        err);
    REQUIRE(ok);
    REQUIRE(err.empty());

    REQUIRE_EQ(readFile(target),  newBin);
    REQUIRE_EQ(readFile(sigPath), newSig);

    // Temp files must be cleaned up
    REQUIRE(std::fopen((target + ".upgrade_tmp").c_str(), "rb") == nullptr);
    REQUIRE(std::fopen((sigPath + ".upgrade_tmp").c_str(), "rb") == nullptr);
}

TEST_CASE("writeUpgradeAtomically: fails if target directory is unwritable path")
{
    std::string err;
    bool ok = ntm::upgrade::writeUpgradeAtomically(
        "/nonexistent_dir/ntm_server_binary",
        reinterpret_cast<const std::uint8_t *>("x"), 1,
        reinterpret_cast<const std::uint8_t *>("y"), 1,
        err);
    REQUIRE(!ok);
    REQUIRE(!err.empty());
}
