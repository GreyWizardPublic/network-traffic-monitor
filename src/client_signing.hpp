#pragma once
// client_signing.hpp — ML-DSA-65 client binary verification.
// Wraps server_signing.hpp for use by:
//   1. client_main.cpp  — startup self-verification
//   2. updater.cpp      — verify downloaded binary before applying
//
// clientSelfPath() resolves the running binary's absolute path:
//   Linux:   /proc/self/exe via readlink
//   Windows: GetModuleFileNameW

#include "server_signing.hpp"

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <unistd.h>
#  include <climits>
#endif

namespace ntm::signing
{

// Returns the absolute path of the currently running binary.
// Returns an empty string on failure.
inline std::string clientSelfPath()
{
#ifdef _WIN32
    wchar_t buf[32768] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
    if (n == 0) return {};
    // Convert wide string to narrow (UTF-8 approximation via filesystem)
    // Use the simple char version for ASCII-safe paths
    char narrow[32768] = {};
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, narrow, sizeof(narrow), nullptr, nullptr);
    return std::string(narrow);
#else
    char buf[PATH_MAX] = {};
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return std::string(buf);
#endif
}

// Verify the client binary at binaryPath against its .sig file.
// Uses the embedded kBuildPublicKeyDer (same key as server).
// sigPath defaults to binaryPath + ".sig" when empty.
inline bool verifyClientSignature(const std::string &binaryPath,
                                   const std::string &sigPath,
                                   std::string       &errOut)
{
    const std::string sp = sigPath.empty() ? binaryPath + ".sig" : sigPath;
    return verifySignatureWithKey(
        binaryPath, sp,
        kBuildPublicKeyDer.data(),
        kBuildPublicKeyDer.size(),
        errOut);
}

// In-memory variant — verify binary + signature already loaded into RAM.
// Used by updater.cpp to verify a downloaded binary before writing to disk.
inline bool verifyClientSignatureBytes(
    const std::vector<std::uint8_t> &binData,
    const std::vector<std::uint8_t> &sigData,
    std::string                     &errOut)
{
    return verifySignatureWithKeyBytes(
        binData, sigData,
        kBuildPublicKeyDer.data(),
        kBuildPublicKeyDer.size(),
        errOut);
}

// Testable overload — accepts any DER public key (for unit tests with generated key pairs).
inline bool verifyClientSignatureBytesWithKey(
    const std::vector<std::uint8_t> &binData,
    const std::vector<std::uint8_t> &sigData,
    const std::uint8_t              *derPubKey,
    std::size_t                      derPubKeyLen,
    std::string                     &errOut)
{
    return verifySignatureWithKeyBytes(
        binData, sigData,
        derPubKey,
        derPubKeyLen,
        errOut);
}

} // namespace ntm::signing
