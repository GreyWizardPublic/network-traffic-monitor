// test_server_signing.cpp — unit tests for src/server_signing.hpp
//
// Tests the ML-DSA-65 binary signature verification logic.
// Each test generates a fresh temporary key pair using the OpenSSL CLI so
// no pre-committed test keys are needed.  The production public key embedded
// in build_pubkey.hpp is NOT used here; tests supply their own key pair.
//
// Tests cover:
//   - valid signature verifies successfully
//   - valid signature with a different public key fails
//   - binary file tampered (byte flip) → verification fails
//   - signature file truncated → verification fails
//   - binary file missing → error
//   - signature file missing → error
//   - empty binary → error
//   - empty signature → error

#include "server_signing.hpp"
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

// Write data to a temp file.  Returns the path.
std::string writeTempFile(const std::string &suffix,
                          const std::uint8_t *data, std::size_t len)
{
    const char *tmp = std::getenv("TMPDIR");
    std::string path = std::string(tmp ? tmp : "/tmp")
                       + "/ntm_test_signing_" + suffix;
    std::FILE *f = std::fopen(path.c_str(), "wb");
    if (f)
    {
        if (len > 0) std::fwrite(data, 1, len, f);
        std::fclose(f);
    }
    return path;
}

std::string writeTempFile(const std::string &suffix, const std::string &s)
{
    return writeTempFile(suffix,
                         reinterpret_cast<const std::uint8_t *>(s.data()),
                         s.size());
}

// Read a file into a vector.
std::vector<std::uint8_t> readFile(const std::string &path)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::rewind(f);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz < 0 ? 0 : sz));
    if (sz > 0)
        std::fread(buf.data(), 1, static_cast<std::size_t>(sz), f);
    std::fclose(f);
    return buf;
}

// Run a shell command; return true if exit code == 0.
bool shell(const std::string &cmd)
{
    return std::system(cmd.c_str()) == 0;
}

// Generate a temporary ML-DSA-65 key pair.
// privPath / pubDer are populated on success.  Returns false on failure.
bool makeTempKeyPair(std::string &privPath,
                     std::vector<std::uint8_t> &pubDer)
{
    privPath           = "/tmp/ntm_test_signing_priv.pem";
    std::string pubDerPath = "/tmp/ntm_test_signing_pub.der";

    if (!shell("openssl genpkey -algorithm ML-DSA-65 -out "
               + privPath + " 2>/dev/null"))
        return false;
    if (!shell("openssl pkey -in " + privPath
               + " -pubout -outform DER -out " + pubDerPath + " 2>/dev/null"))
        return false;
    pubDer = readFile(pubDerPath);
    return !pubDer.empty();
}

// Sign a file with a private key PEM; write the signature to sigPath.
bool signFile(const std::string &filePath, const std::string &privPath,
              const std::string &sigPath)
{
    return shell("openssl pkeyutl -sign -inkey " + privPath
                 + " -in " + filePath + " -out " + sigPath + " 2>/dev/null");
}

// ── Fixture ──────────────────────────────────────────────────────────────────
// One key pair shared across tests to keep the test run fast.

struct KeyFixture
{
    std::string                privPath;
    std::vector<std::uint8_t>  pubDer;
    bool                       ok = false;

    KeyFixture() { ok = makeTempKeyPair(privPath, pubDer); }
};

static KeyFixture g_kf; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

} // namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("server_signing: key fixture created successfully")
{
    REQUIRE(g_kf.ok);          // makeTempKeyPair failed — is OpenSSL 3.3+ installed?
    REQUIRE(!g_kf.pubDer.empty());
    // ML-DSA-65 SPKI DER is 1974 bytes
    REQUIRE_EQ(g_kf.pubDer.size(), std::size_t(1974));
}

TEST_CASE("server_signing: valid signature verifies successfully")
{
    REQUIRE(g_kf.ok);

    const std::string payload = "ntm-server test binary payload 1234567890";
    std::string binPath = writeTempFile("bin_valid.bin", payload);
    std::string sigPath = binPath + ".sig";

    REQUIRE(signFile(binPath, g_kf.privPath, sigPath));

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(ok);   // valid signature must verify
}

TEST_CASE("server_signing: different public key → verification fails")
{
    REQUIRE(g_kf.ok);

    const std::string payload = "ntm-server test binary payload other key";
    std::string binPath = writeTempFile("bin_wrongkey.bin", payload);
    std::string sigPath = binPath + ".sig";
    REQUIRE(signFile(binPath, g_kf.privPath, sigPath));

    // Generate a second, unrelated key pair
    std::string priv2;
    std::vector<std::uint8_t> pub2;
    REQUIRE(makeTempKeyPair(priv2, pub2));

    // Verify with the WRONG key — must fail
    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        pub2.data(), pub2.size(),
        err);
    REQUIRE(!ok);  // wrong key must reject the signature
}

TEST_CASE("server_signing: tampered binary → verification fails")
{
    REQUIRE(g_kf.ok);

    std::string payload = "ntm-server test binary payload tamper test ABCDEF";
    std::string binPath = writeTempFile("bin_tamper.bin", payload);
    std::string sigPath = binPath + ".sig";
    REQUIRE(signFile(binPath, g_kf.privPath, sigPath));

    // Flip one byte in the middle of the binary
    auto binData = readFile(binPath);
    REQUIRE(!binData.empty());
    binData[binData.size() / 2] ^= 0xFF;
    writeTempFile("bin_tamper.bin", binData.data(), binData.size());

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(!ok);  // tampered binary must fail
}

TEST_CASE("server_signing: truncated signature → verification fails")
{
    REQUIRE(g_kf.ok);

    const std::string payload = "ntm-server test binary payload truncated sig";
    std::string binPath = writeTempFile("bin_trunc.bin", payload);
    std::string sigPath = binPath + ".sig";
    REQUIRE(signFile(binPath, g_kf.privPath, sigPath));

    // Truncate the signature to 100 bytes (ML-DSA-65 sig is 3309 bytes)
    auto sigData = readFile(sigPath);
    REQUIRE(sigData.size() > 100);
    sigData.resize(100);
    writeTempFile("bin_trunc.bin.sig", sigData.data(), sigData.size());

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(!ok);  // truncated signature must fail
}

TEST_CASE("server_signing: missing binary file → error returned")
{
    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        "/tmp/ntm_test_signing_NONEXISTENT.bin",
        "/tmp/ntm_test_signing_NONEXISTENT.bin.sig",
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(!ok);
    REQUIRE(!err.empty());
}

TEST_CASE("server_signing: missing signature file → error returned")
{
    REQUIRE(g_kf.ok);

    const std::string payload = "ntm-server test binary payload nosig";
    std::string binPath = writeTempFile("bin_nosig.bin", payload);

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath,
        "/tmp/ntm_test_signing_NONEXISTENT.sig",
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(!ok);
    REQUIRE(!err.empty());
}

TEST_CASE("server_signing: empty binary → error returned")
{
    REQUIRE(g_kf.ok);

    // Write a zero-length binary file
    std::string binPath = "/tmp/ntm_test_signing_empty.bin";
    {
        std::FILE *f = std::fopen(binPath.c_str(), "wb");
        if (f) std::fclose(f);
    }
    // Sign the empty file (OpenSSL can sign empty payloads)
    std::string sigPath = binPath + ".sig";
    signFile(binPath, g_kf.privPath, sigPath);

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    // Empty binary is rejected as a safety check
    REQUIRE(!ok);
    REQUIRE(!err.empty());
}

TEST_CASE("server_signing: empty signature → error returned")
{
    REQUIRE(g_kf.ok);

    const std::string payload = "ntm-server test binary payload emptysig";
    std::string binPath = writeTempFile("bin_emptysig.bin", payload);

    // Write a zero-length .sig file
    std::string sigPath = binPath + ".sig";
    {
        std::FILE *f = std::fopen(sigPath.c_str(), "wb");
        if (f) std::fclose(f);
    }

    std::string err;
    bool ok = ntm::signing::verifySignatureWithKey(
        binPath, sigPath,
        g_kf.pubDer.data(), g_kf.pubDer.size(),
        err);
    REQUIRE(!ok);
    REQUIRE(!err.empty());
}
