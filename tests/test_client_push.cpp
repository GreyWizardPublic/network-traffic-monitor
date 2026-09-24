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
#include <filesystem>
#include <string>
#include <vector>

namespace
{

bool shell(const std::string &cmd)
{
#ifdef _WIN32
    // cmd.exe /c strips the first and last quote of a command that starts with
    // one — wrap the whole line so quoted paths survive.
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

// openssl from PATH; on Windows fall back to the MSYS2 toolchain copy, since
// ntm-tests-windows.exe is often run directly without mingw64\bin on PATH.
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
    privPath = tmpPath("ntm_test_cpush_priv_" + std::to_string(idx) + ".pem");
    std::string pubDerPath = tmpPath("ntm_test_cpush_pub_" + std::to_string(idx) + ".der");
    if (!shell(openssl() + " genpkey -algorithm ML-DSA-65 -out " + quotePath(privPath) + kNoStderr))
        return false;
    if (!shell(openssl() + " pkey -in " + quotePath(privPath)
               + " -pubout -outform DER -out " + quotePath(pubDerPath) + kNoStderr))
        return false;
    auto raw = readFileStr(pubDerPath);
    pubDer.assign(raw.begin(), raw.end());
    return !pubDer.empty();
}

std::vector<std::uint8_t> signMsg(const std::string &privPath,
                                   const std::vector<std::uint8_t> &msg)
{
    const std::string msgPath = tmpPath("ntm_test_cpush_msg.bin");
    const std::string sigPath = tmpPath("ntm_test_cpush_sig.bin");
    FILE *f = std::fopen(msgPath.c_str(), "wb");
    if (f) { std::fwrite(msg.data(), 1, msg.size(), f); std::fclose(f); }
    shell(openssl() + " pkeyutl -sign -inkey " + quotePath(privPath)
          + " -in " + quotePath(msgPath) + " -out " + quotePath(sigPath) + " -rawin" + kNoStderr);
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
