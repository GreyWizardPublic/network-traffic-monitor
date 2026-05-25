// test_client_signing.cpp — unit tests for src/client_signing.hpp
//
// Tests:
//   verifyClientSignatureBytesWithKey — valid sig, tampered binary, tampered sig,
//                                       wrong key, empty binary, empty sig
//   clientSelfPath — smoke test (non-empty, not a crash)

#include "client_signing.hpp"
#include "ntm_test.hpp"

#include <cstdlib>
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

std::vector<std::uint8_t> readFileVec(const std::string &path)
{
    auto s = readFileStr(path);
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// Generate a test ML-DSA-65 key pair. Uses unique filenames to avoid cross-test interference.
static int g_csigningKeyIdx = 0;
bool makeTmpKeyPair(std::string &privPath, std::vector<std::uint8_t> &pubDer)
{
    int idx = g_csigningKeyIdx++;
    privPath = "/tmp/ntm_test_csigning_priv_" + std::to_string(idx) + ".pem";
    std::string pubDerPath = "/tmp/ntm_test_csigning_pub_" + std::to_string(idx) + ".der";
    if (!shell("openssl genpkey -algorithm ML-DSA-65 -out " + privPath + " 2>/dev/null"))
        return false;
    if (!shell("openssl pkey -in " + privPath
               + " -pubout -outform DER -out " + pubDerPath + " 2>/dev/null"))
        return false;
    auto raw = readFileStr(pubDerPath);
    pubDer.assign(raw.begin(), raw.end());
    return !pubDer.empty();
}

// Sign binary bytes with a private key; return sig bytes.
std::vector<std::uint8_t> signBinary(const std::string &privPath,
                                      const std::vector<std::uint8_t> &binData)
{
    const std::string binTmp = "/tmp/ntm_test_csigning_bin.bin";
    const std::string sigTmp = "/tmp/ntm_test_csigning_sig.bin";
    FILE *f = std::fopen(binTmp.c_str(), "wb");
    if (f) { std::fwrite(binData.data(), 1, binData.size(), f); std::fclose(f); }
    shell("openssl pkeyutl -sign -inkey " + privPath
          + " -in " + binTmp + " -out " + sigTmp + " -rawin 2>/dev/null");
    return readFileVec(sigTmp);
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
// verifyClientSignatureBytesWithKey
// ---------------------------------------------------------------------------

TEST_CASE("verifyClientSignatureBytesWithKey: valid signature")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> bin = {'h','e','l','l','o',' ','c','l','i','e','n','t'};
    auto sig = signBinary(g_kf.priv, bin);
    REQUIRE(!sig.empty());

    std::string err;
    REQUIRE(ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(err.empty());
}

TEST_CASE("verifyClientSignatureBytesWithKey: tampered binary")
{
    REQUIRE(g_kf.ok);
    std::vector<std::uint8_t> bin = {'t','a','m','p','e','r'};
    auto sig = signBinary(g_kf.priv, bin);
    REQUIRE(!sig.empty());

    bin[0] ^= 0xFF; // tamper
    std::string err;
    REQUIRE(!ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(!err.empty());
}

TEST_CASE("verifyClientSignatureBytesWithKey: tampered signature")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> bin = {'s','i','g','t','e','s','t'};
    auto sig = signBinary(g_kf.priv, bin);
    REQUIRE(!sig.empty());

    sig[0] ^= 0xFF; // tamper
    std::string err;
    REQUIRE(!ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(!err.empty());
}

TEST_CASE("verifyClientSignatureBytesWithKey: wrong key")
{
    REQUIRE(g_kf.ok);
    // Generate a second key pair
    std::string priv2;
    std::vector<std::uint8_t> pub2;
    REQUIRE(makeTmpKeyPair(priv2, pub2));

    const std::vector<std::uint8_t> bin = {'w','r','o','n','g','k','e','y'};
    auto sig = signBinary(g_kf.priv, bin); // signed with key 1
    REQUIRE(!sig.empty());

    std::string err;
    REQUIRE(!ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, pub2.data(), pub2.size(), err)); // verify with key 2
    REQUIRE(!err.empty());
}

TEST_CASE("verifyClientSignatureBytesWithKey: empty binary rejected")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> bin = {};
    const std::vector<std::uint8_t> sig = {0x01, 0x02};
    std::string err;
    REQUIRE(!ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(!err.empty());
}

TEST_CASE("verifyClientSignatureBytesWithKey: empty signature rejected")
{
    REQUIRE(g_kf.ok);
    const std::vector<std::uint8_t> bin = {'d','a','t','a'};
    const std::vector<std::uint8_t> sig = {};
    std::string err;
    REQUIRE(!ntm::signing::verifyClientSignatureBytesWithKey(
        bin, sig, g_kf.pub.data(), g_kf.pub.size(), err));
    REQUIRE(!err.empty());
}

// ---------------------------------------------------------------------------
// clientSelfPath
// ---------------------------------------------------------------------------

TEST_CASE("clientSelfPath: returns non-empty path")
{
    std::string path = ntm::signing::clientSelfPath();
    // Should be non-empty and point to a file that exists
    REQUIRE(!path.empty());
}
