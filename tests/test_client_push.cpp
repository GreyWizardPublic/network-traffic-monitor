// test_client_push.cpp — unit tests for src/client_push.hpp and client push auth logic.
//
// Tests:
//   parseClientBinaryFilename — valid Linux/Windows names, edge cases
//   isKnownClientPlatform     — known and unknown platforms
//   Push auth round-trip      — valid proof, wrong key, tampered nonce/hash

#include "client_push.hpp"
#include "server_upgrade.hpp"
#include "server_signing.hpp"
#include "ntm_test.hpp"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{

bool shell(const std::string &cmd) { return std::system(cmd.c_str()) == 0; }

std::string readFileStr(const std::string &path)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return "";
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::rewind(f);
    if (sz <= 0) { std::fclose(f); return ""; }
    std::string s(static_cast<std::size_t>(sz), '\0');
    std::fread(s.data(), 1, static_cast<std::size_t>(sz), f);
    std::fclose(f);
    return s;
}

static int g_cpushKeyIdx = 0;
bool makeTmpKeyPair(std::string &privPath, std::vector<std::uint8_t> &pubDer)
{
    int idx = g_cpushKeyIdx++;
    privPath = "/tmp/ntm_test_cpush_priv_" + std::to_string(idx) + ".pem";
    std::string pubDerPath = "/tmp/ntm_test_cpush_pub_" + std::to_string(idx) + ".der";
    if (!shell("openssl genpkey -algorithm ML-DSA-65 -out " + privPath + " 2>/dev/null"))
        return false;
    if (!shell("openssl pkey -in " + privPath
               + " -pubout -outform DER -out " + pubDerPath + " 2>/dev/null"))
        return false;
    auto raw = readFileStr(pubDerPath);
    pubDer.assign(raw.begin(), raw.end());
    return !pubDer.empty();
}

std::vector<std::uint8_t> signMsg(const std::string &privPath,
                                   const std::vector<std::uint8_t> &msg)
{
    const std::string msgPath = "/tmp/ntm_test_cpush_msg.bin";
    const std::string sigPath = "/tmp/ntm_test_cpush_sig.bin";
    FILE *f = std::fopen(msgPath.c_str(), "wb");
    if (f) { std::fwrite(msg.data(), 1, msg.size(), f); std::fclose(f); }
    shell("openssl pkeyutl -sign -inkey " + privPath
          + " -in " + msgPath + " -out " + sigPath + " -rawin 2>/dev/null");
    auto raw = readFileStr(sigPath);
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

std::vector<std::uint8_t> makeAuthProof(const std::string &privPath,
                                         const std::vector<std::uint8_t> &nonce,
                                         const std::vector<std::uint8_t> &binary)
{
    auto hash = ntm::upgrade::sha3_256(binary);
    std::vector<std::uint8_t> msg;
    msg.insert(msg.end(), nonce.begin(), nonce.end());
    msg.insert(msg.end(), hash.begin(),  hash.end());
    return signMsg(privPath, msg);
}

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
// parseClientBinaryFilename
// ---------------------------------------------------------------------------

TEST_CASE("parseClientBinaryFilename: valid Linux name")
{
    auto r = ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-1.15.0.0");
    REQUIRE(r.valid);
    REQUIRE_EQ(r.platform, std::string("linux-amd64"));
    REQUIRE_EQ(r.version,  std::string("1.15.0.0"));
    REQUIRE(!r.isWindows);
}

TEST_CASE("parseClientBinaryFilename: valid Windows name with .exe")
{
    auto r = ntm::client::parseClientBinaryFilename("ntm-client-windows-amd64-1.15.0.0.exe");
    REQUIRE(r.valid);
    REQUIRE_EQ(r.platform, std::string("windows-amd64"));
    REQUIRE_EQ(r.version,  std::string("1.15.0.0"));
    REQUIRE(r.isWindows);
}

TEST_CASE("parseClientBinaryFilename: 3-part version accepted")
{
    auto r = ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-1.15.0");
    REQUIRE(r.valid);
    REQUIRE_EQ(r.version, std::string("1.15.0"));
}

TEST_CASE("parseClientBinaryFilename: wrong prefix")
{
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-server-linux-amd64-1.0.0.0").valid);
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client1.0.0.0").valid);
}

TEST_CASE("parseClientBinaryFilename: missing version")
{
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64").valid);
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-").valid);
}

TEST_CASE("parseClientBinaryFilename: invalid version characters")
{
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-1.x.0.0").valid);
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-1.0.0.").valid);
}

TEST_CASE("parseClientBinaryFilename: empty string")
{
    REQUIRE(!ntm::client::parseClientBinaryFilename("").valid);
}

TEST_CASE("parseClientBinaryFilename: 5-part version rejected")
{
    REQUIRE(!ntm::client::parseClientBinaryFilename("ntm-client-linux-amd64-1.0.0.0.0").valid);
}

// ---------------------------------------------------------------------------
// isKnownClientPlatform
// ---------------------------------------------------------------------------

TEST_CASE("isKnownClientPlatform: known platforms")
{
    REQUIRE(ntm::client::isKnownClientPlatform("linux-amd64"));
    REQUIRE(ntm::client::isKnownClientPlatform("windows-amd64"));
}

TEST_CASE("isKnownClientPlatform: unknown platforms")
{
    REQUIRE(!ntm::client::isKnownClientPlatform("darwin-amd64"));
    REQUIRE(!ntm::client::isKnownClientPlatform("linux-arm64"));
    REQUIRE(!ntm::client::isKnownClientPlatform(""));
}

// ---------------------------------------------------------------------------
// Push auth round-trip (verifyUpgradeAuth reused for client push)
// ---------------------------------------------------------------------------

TEST_CASE("client push auth: valid proof accepted")
{
    REQUIRE(g_kf.ok);
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate(300);
    REQUIRE(!nonce.empty());

    const std::vector<std::uint8_t> binary = {'c','l','i','e','n','t','b','i','n'};
    const auto nonceBytes = ntm::upgrade::hexDecode(nonce);
    auto proof = makeAuthProof(g_kf.priv, nonceBytes, binary);
    REQUIRE(!proof.empty());

    const auto binaryHash = ntm::upgrade::sha3_256(binary);
    std::string err;
    REQUIRE(ntm::upgrade::verifyUpgradeAuth(
        nonceBytes, binaryHash, proof,
        g_kf.pub.data(), g_kf.pub.size(), err));
}

TEST_CASE("client push auth: wrong key rejected")
{
    REQUIRE(g_kf.ok);
    std::string priv2;
    std::vector<std::uint8_t> pub2;
    REQUIRE(makeTmpKeyPair(priv2, pub2));

    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate(300);
    const auto nonceBytes = ntm::upgrade::hexDecode(nonce);
    const std::vector<std::uint8_t> binary = {'w','r','o','n','g','k','e','y'};
    auto proof = makeAuthProof(g_kf.priv, nonceBytes, binary); // signed with key 1

    const auto binaryHash = ntm::upgrade::sha3_256(binary);
    std::string err;
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth(
        nonceBytes, binaryHash, proof,
        pub2.data(), pub2.size(), err)); // verified with key 2
}

TEST_CASE("client push auth: tampered nonce rejected")
{
    REQUIRE(g_kf.ok);
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate(300);
    auto nonceBytes = ntm::upgrade::hexDecode(nonce);
    const std::vector<std::uint8_t> binary = {'t','a','m','p','e','r'};
    auto proof = makeAuthProof(g_kf.priv, nonceBytes, binary);
    REQUIRE(!proof.empty());

    nonceBytes[0] ^= 0xFF; // tamper nonce
    const auto binaryHash = ntm::upgrade::sha3_256(binary);
    std::string err;
    REQUIRE(!ntm::upgrade::verifyUpgradeAuth(
        nonceBytes, binaryHash, proof,
        g_kf.pub.data(), g_kf.pub.size(), err));
}

TEST_CASE("client push auth: replay (double-spend nonce) rejected")
{
    REQUIRE(g_kf.ok);
    ntm::upgrade::NonceStore store;
    std::string nonce = store.generate(300);
    const auto nonceBytes = ntm::upgrade::hexDecode(nonce);
    const std::vector<std::uint8_t> binary = {'r','e','p','l','a','y'};
    auto proof = makeAuthProof(g_kf.priv, nonceBytes, binary);

    REQUIRE(store.consume(nonce)); // first use succeeds
    REQUIRE(!store.consume(nonce)); // replay rejected
}

TEST_CASE("client push version: parseSemver 4-part for version comparison")
{
    using ntm::upgrade::parseSemver;
    auto v1 = parseSemver("1.14.1.0");
    auto v2 = parseSemver("1.15.0.0");
    REQUIRE(v1.valid);
    REQUIRE(v2.valid);
    REQUIRE(v2 > v1);
    REQUIRE(v1 < v2);
    REQUIRE(!(v1 == v2));
}
