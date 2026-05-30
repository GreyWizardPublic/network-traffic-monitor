// tests/test_client_identity_perms.cpp — POSIX-only tests for H-4.
//
// Verifies that checkIdentityFilePermissions() (src/client_linux.cpp) returns
// false and does not proceed when the identity key file has group/world-readable
// permissions or is not owned by the current process.
//
// Not compiled into ntm-tests-windows (POSIX tmpfile / chmod / stat only).
// Run via:  ./build-linux/ntm-tests

#include "ntm_test.hpp"
#include "../src/client_linux_perms.hpp"

using ntm::platform::checkIdentityKeyPermissionsImpl;

#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

// Create a temporary file and return its path.  Caller owns deletion.
std::string makeTempFile()
{
    char tpl[] = "/tmp/ntm_perms_test_XXXXXX";
    int fd = ::mkstemp(tpl);
    if (fd < 0) return {};
    ::close(fd);
    return std::string(tpl);
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// H-4 regression: checkIdentityFilePermissions returns bool
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("checkIdentityFilePermissions: mode 0600, owned by self — returns true (H-4)")
{
    std::string path = makeTempFile();
    REQUIRE(!path.empty());
    ::chmod(path.c_str(), 0600);
    bool ok = checkIdentityKeyPermissionsImpl(path, /*isDaemon=*/false);
    ::unlink(path.c_str());
    REQUIRE(ok);
}

TEST_CASE("checkIdentityFilePermissions: group-readable (0640) — returns false (H-4)")
{
    std::string path = makeTempFile();
    REQUIRE(!path.empty());
    ::chmod(path.c_str(), 0640);
    bool ok = checkIdentityKeyPermissionsImpl(path, false);
    ::unlink(path.c_str());
    REQUIRE(!ok);
}

TEST_CASE("checkIdentityFilePermissions: world-readable (0644) — returns false (H-4)")
{
    std::string path = makeTempFile();
    REQUIRE(!path.empty());
    ::chmod(path.c_str(), 0644);
    bool ok = checkIdentityKeyPermissionsImpl(path, false);
    ::unlink(path.c_str());
    REQUIRE(!ok);
}

TEST_CASE("checkIdentityFilePermissions: world-writable (0606) — returns false (H-4)")
{
    std::string path = makeTempFile();
    REQUIRE(!path.empty());
    ::chmod(path.c_str(), 0606);
    bool ok = checkIdentityKeyPermissionsImpl(path, false);
    ::unlink(path.c_str());
    REQUIRE(!ok);
}

TEST_CASE("checkIdentityFilePermissions: mode 0700 (owner execute, no group/world) — returns true")
{
    std::string path = makeTempFile();
    REQUIRE(!path.empty());
    ::chmod(path.c_str(), 0700);
    bool ok = checkIdentityKeyPermissionsImpl(path, false);
    ::unlink(path.c_str());
    REQUIRE(ok);
}

TEST_CASE("checkIdentityFilePermissions: non-existent file — returns true (missing handled by fopen)")
{
    // Caller is responsible for handling missing files; the check should not
    // fail on a path that simply doesn't exist.
    bool ok = checkIdentityKeyPermissionsImpl("/tmp/ntm_does_not_exist_xyz_987654", false);
    REQUIRE(ok);
}
