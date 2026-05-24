#pragma once
// server_signing.hpp — ML-DSA-65 binary signature verification for ntm-server startup.
//
// ALL functions here are pure logic: file I/O + OpenSSL EVP only.
// No syslog, no global state, no platform singletons.
// This makes verification fully testable outside the server process.
//
// Algorithm: ML-DSA-65 (CRYSTALS-Dilithium Level 3, NIST FIPS 204)
// Key format: SubjectPublicKeyInfo DER (d2i_PUBKEY compatible)
// OpenSSL 3.3+ required (ML-DSA-65 in default provider since 3.3).
//
// Production entry point:
//   verifyServerSignature(binaryPath, sigPath, errOut)
//   — uses the embedded public key from build_pubkey.hpp
//
// Test entry point:
//   verifySignatureWithKey(binaryPath, sigPath, derPubKey, derLen, errOut)
//   — accepts any DER public key, allowing tests to use their own key pairs

#include "build_pubkey.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace ntm::signing
{

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace detail
{

// Read an entire file into a vector.  Returns false on I/O error.
inline bool readFile(const std::string &path, std::vector<std::uint8_t> &out,
                     std::string &errOut)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
    {
        errOut = "cannot open '" + path + "'";
        return false;
    }
    if (std::fseek(f, 0, SEEK_END) != 0)
    {
        std::fclose(f);
        errOut = "fseek failed on '" + path + "'";
        return false;
    }
    long sz = std::ftell(f);
    if (sz < 0)
    {
        std::fclose(f);
        errOut = "ftell failed on '" + path + "'";
        return false;
    }
    std::rewind(f);
    out.resize(static_cast<std::size_t>(sz));
    if (sz > 0 && std::fread(out.data(), 1, static_cast<std::size_t>(sz), f) !=
                      static_cast<std::size_t>(sz))
    {
        std::fclose(f);
        errOut = "short read on '" + path + "'";
        return false;
    }
    std::fclose(f);
    return true;
}

// Drain the OpenSSL error queue into a human-readable string.
inline std::string opensslErrors()
{
    std::string s;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0)
    {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!s.empty()) s += "; ";
        s += buf;
    }
    return s.empty() ? "(no OpenSSL error)" : s;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Testable inner function — accepts any DER public key
// ---------------------------------------------------------------------------

// Verify that the ML-DSA-65 signature in sigPath covers the bytes of binaryPath,
// using the provided DER-encoded SubjectPublicKeyInfo public key.
// Returns true on success; errOut is set on failure.
inline bool verifySignatureWithKey(
    const std::string  &binaryPath,
    const std::string  &sigPath,
    const std::uint8_t *derPubKey,
    std::size_t         derPubKeyLen,
    std::string        &errOut)
{
    // Read binary and signature
    std::vector<std::uint8_t> binData, sigData;
    if (!detail::readFile(binaryPath, binData, errOut)) return false;
    if (!detail::readFile(sigPath,    sigData, errOut)) return false;

    if (binData.empty())
    {
        errOut = "binary file is empty: " + binaryPath;
        return false;
    }
    if (sigData.empty())
    {
        errOut = "signature file is empty: " + sigPath;
        return false;
    }

    // Load public key from DER bytes
    const std::uint8_t *p = derPubKey;
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr,
                                &p,
                                static_cast<long>(derPubKeyLen));
    if (!pkey)
    {
        errOut = "failed to load public key: " + detail::opensslErrors();
        return false;
    }

    // Verify: EVP_DigestVerifyInit with md=NULL (ML-DSA handles its own hashing)
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        errOut = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1)
    {
        errOut = "EVP_DigestVerifyInit failed: " + detail::opensslErrors();
    }
    else
    {
        int rc = EVP_DigestVerify(ctx,
                                  sigData.data(), sigData.size(),
                                  binData.data(), binData.size());
        if (rc == 1)
        {
            ok = true;
        }
        else
        {
            errOut = "signature verification failed: " + detail::opensslErrors();
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// Production entry point — uses the embedded build public key
// ---------------------------------------------------------------------------

// Verify the server binary at binaryPath against its ML-DSA-65 signature.
// The signature file is binaryPath + ".sig" unless sigPath is specified.
// Returns true if the signature is valid; errOut describes the failure otherwise.
inline bool verifyServerSignature(const std::string &binaryPath,
                                   const std::string &sigPath,
                                   std::string       &errOut)
{
    return verifySignatureWithKey(
        binaryPath, sigPath,
        kBuildPublicKeyDer.data(),
        kBuildPublicKeyDer.size(),
        errOut);
}

} // namespace ntm::signing
