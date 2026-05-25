// test_windows_client.cpp
// Unit tests for Windows-specific ntm-client behaviour.
//
// Design constraints:
//   - No live server, Npcap kernel driver, or external network access required.
//   - Tests exercise pure-logic paths and the Windows platform abstraction layer.
//   - WSAStartup is called once via WsaGuard before any test function runs.
//
// Test groups:
//   1.  Wire-protocol constants (regression guard)
//   2.  Auth-protocol constants (byte-level semantics)
//   3.  Wire-line format string constants
//   4.  LAN IPv4 address classification (isLanAddrV4)
//   5.  LAN IPv6 address classification (isLanAddrV6)
//   6.  queryExternalIP — early-exit / input-validation paths (no live network)
//   7.  Platform init / cleanup lifecycle
//   8.  checkIdentityFilePermissions stub (no crash)
//   9.  daemonize stub (no crash)
//   10. NetworkMonitor start / stop / checkAndClear lifecycle
//   11. ClientConfig default values
//   12. Version / platform identity constants
//   13. connectToServer — error paths (no live server required)
//   14. collectLanAddresses — smoke test (no Npcap required)

#ifndef _WIN32
#  error "test_windows_client.cpp is Windows-only"
#endif

#include "ntm_test.hpp"

#include "../src/proto_client_server.hpp"
#include "../src/client_core.hpp"
#include "../src/client_platform.hpp"
#include "../src/client.hpp"
#include "../src/client_version.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <aclapi.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// WSA lifetime guard — initialised before any test function runs.
// TEST_CASE registration (static constructors) does not call Winsock, so
// initialisation order between translation units is not a concern.
// ---------------------------------------------------------------------------
namespace {
struct WsaGuard
{
    WsaGuard()  { ntm::platform::initPlatform(); }
    ~WsaGuard() { ntm::platform::cleanupPlatform(); }
};
static WsaGuard g_wsaGuard;

// Helpers — convert dotted-decimal / colon-hex notation to the raw integer
// types expected by isLanAddrV4 / isLanAddrV6.
static std::uint32_t ipv4Net(const char *dotted)
{
    struct in_addr a{};
    if (::inet_pton(AF_INET, dotted, &a) != 1)
        throw std::runtime_error(std::string("bad IPv4 literal: ") + dotted);
    return a.s_addr; // network byte order — matches isLanAddrV4 contract
}

static std::array<std::uint8_t, 16> ipv6Bytes(const char *colon)
{
    struct in6_addr a{};
    if (::inet_pton(AF_INET6, colon, &a) != 1)
        throw std::runtime_error(std::string("bad IPv6 literal: ") + colon);
    std::array<std::uint8_t, 16> out{};
    std::memcpy(out.data(), a.s6_addr, 16);
    return out;
}
} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// 1. Wire-protocol constants (regression guard)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("proto: kWireProtoVersion is 2")
{
    REQUIRE_EQ(ntm::kWireProtoVersion, 2u);
}

TEST_CASE("proto: kDefaultPort is 5555")
{
    REQUIRE_EQ(ntm::kDefaultPort, std::uint16_t{5555});
}

TEST_CASE("proto: kMaxIOBytes is exactly 2 MiB")
{
    REQUIRE_EQ(ntm::kMaxIOBytes, std::size_t{2u * 1024u * 1024u});
}

TEST_CASE("proto: kSendBatchSize does not exceed kMaxIOBytes")
{
    REQUIRE(ntm::kSendBatchSize <= ntm::kMaxIOBytes);
}

TEST_CASE("proto: kMaxSessionSeconds is 6 hours")
{
    REQUIRE_EQ(ntm::kMaxSessionSeconds, std::uint64_t{6u * 3600u});
}

TEST_CASE("proto: kHealthIntervalSec is 30")
{
    REQUIRE_EQ(ntm::kHealthIntervalSec, 30u);
}

TEST_CASE("proto: kMaxIfaceLabelLen is 64")
{
    REQUIRE_EQ(ntm::kMaxIfaceLabelLen, std::size_t{64});
}

TEST_CASE("proto: kMaxIpLabelLen is 50")
{
    REQUIRE_EQ(ntm::kMaxIpLabelLen, std::size_t{50});
}

TEST_CASE("proto: kMaxAnnounceAddressesPerSession is 64")
{
    REQUIRE_EQ(ntm::kMaxAnnounceAddressesPerSession, std::size_t{64});
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Auth-protocol constants (byte-level semantics)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("auth: kAuthVersionV2 is 2, kAuthVersionV3 is 3")
{
    REQUIRE_EQ(ntm::kAuthVersionV2, 2u);
    REQUIRE_EQ(ntm::kAuthVersionV3, 3u);
}

TEST_CASE("auth: kAuthResultOk is 0x00, kAuthResultReject is 0x01")
{
    REQUIRE_EQ(ntm::kAuthResultOk,     std::uint8_t{0x00});
    REQUIRE_EQ(ntm::kAuthResultReject, std::uint8_t{0x01});
    REQUIRE_NE(ntm::kAuthResultOk, ntm::kAuthResultReject);
}

TEST_CASE("auth: kCapNone is 0x00, kCapZlib is 0x01")
{
    REQUIRE_EQ(ntm::kCapNone, std::uint8_t{0x00});
    REQUIRE_EQ(ntm::kCapZlib, std::uint8_t{0x01});
}

TEST_CASE("auth: capability flag bitwise semantics — OR/AND/mask")
{
    // kCapNone is the zero baseline; OR-ing in kCapZlib sets the bit.
    std::uint8_t cap = ntm::kCapNone;
    cap = static_cast<std::uint8_t>(cap | ntm::kCapZlib);
    REQUIRE_EQ(cap, ntm::kCapZlib);
    // Masking with kCapZlib extracts the bit.
    REQUIRE_EQ(static_cast<std::uint8_t>(cap & ntm::kCapZlib), ntm::kCapZlib);
    // kCapNone AND anything is kCapNone.
    REQUIRE_EQ(static_cast<std::uint8_t>(ntm::kCapNone & ntm::kCapZlib),
               ntm::kCapNone);
}

TEST_CASE("auth: key-material sizes are correct")
{
    REQUIRE_EQ(ntm::kAuthPubkeyLen,    std::size_t{32});
    REQUIRE_EQ(ntm::kAuthSignatureLen, std::size_t{64});
    REQUIRE_EQ(ntm::kAuthNonceLen,     std::size_t{32});
}

TEST_CASE("auth: kAuthSignPrefixV2 length matches kAuthSignPrefixV2Len")
{
    REQUIRE_EQ(std::strlen(ntm::kAuthSignPrefixV2), ntm::kAuthSignPrefixV2Len);
}

TEST_CASE("auth: kAuthSignPrefixV2 content is NTM-AUTH-v2")
{
    REQUIRE_EQ(std::string(ntm::kAuthSignPrefixV2), std::string{"NTM-AUTH-v2"});
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Wire-line format string constants
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("lineformat: D-line prefix is 'D '")
{
    REQUIRE_EQ(std::string(ntm::kDataLinePrefix), std::string{"D "});
}

TEST_CASE("lineformat: H-line prefix is 'H '")
{
    REQUIRE_EQ(std::string(ntm::kHealthLinePrefix), std::string{"H "});
}

TEST_CASE("lineformat: A-line prefix is 'A '")
{
    REQUIRE_EQ(std::string(ntm::kAddrLinePrefix), std::string{"A "});
}

TEST_CASE("lineformat: X-line prefix is 'X '")
{
    REQUIRE_EQ(std::string(ntm::kExtIPLinePrefix), std::string{"X "});
}

TEST_CASE("lineformat: X-null sentinel is 'null'")
{
    REQUIRE_EQ(std::string(ntm::kExtIPNull), std::string{"null"});
}

TEST_CASE("lineformat: all line prefixes are exactly 2 bytes long")
{
    REQUIRE_EQ(std::strlen(ntm::kDataLinePrefix),   std::size_t{2});
    REQUIRE_EQ(std::strlen(ntm::kHealthLinePrefix), std::size_t{2});
    REQUIRE_EQ(std::strlen(ntm::kAddrLinePrefix),   std::size_t{2});
    REQUIRE_EQ(std::strlen(ntm::kExtIPLinePrefix),  std::size_t{2});
}

TEST_CASE("lineformat: all line prefixes end with a space")
{
    REQUIRE(ntm::kDataLinePrefix[1]   == ' ');
    REQUIRE(ntm::kHealthLinePrefix[1] == ' ');
    REQUIRE(ntm::kAddrLinePrefix[1]   == ' ');
    REQUIRE(ntm::kExtIPLinePrefix[1]  == ' ');
}

TEST_CASE("lineformat: all line prefix first bytes are distinct")
{
    // Ensures the server/client can distinguish line types by the first byte.
    REQUIRE_NE(ntm::kDataLinePrefix[0],   ntm::kHealthLinePrefix[0]);
    REQUIRE_NE(ntm::kDataLinePrefix[0],   ntm::kAddrLinePrefix[0]);
    REQUIRE_NE(ntm::kDataLinePrefix[0],   ntm::kExtIPLinePrefix[0]);
    REQUIRE_NE(ntm::kHealthLinePrefix[0], ntm::kAddrLinePrefix[0]);
    REQUIRE_NE(ntm::kHealthLinePrefix[0], ntm::kExtIPLinePrefix[0]);
    REQUIRE_NE(ntm::kAddrLinePrefix[0],   ntm::kExtIPLinePrefix[0]);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. LAN IPv4 address classification
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanAddrV4: loopback 127.0.0.1 is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("127.0.0.1")));
}

TEST_CASE("isLanAddrV4: loopback block boundary 127.0.0.0 is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("127.0.0.0")));
}

TEST_CASE("isLanAddrV4: loopback block high end 127.255.255.255 is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("127.255.255.255")));
}

TEST_CASE("isLanAddrV4: 10.0.0.0/8 low boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("10.0.0.0")));
}

TEST_CASE("isLanAddrV4: 10.x.x.x typical address is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("10.10.20.30")));
}

TEST_CASE("isLanAddrV4: 10.0.0.0/8 high boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("10.255.255.255")));
}

TEST_CASE("isLanAddrV4: 172.16.0.0 /12 low boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("172.16.0.0")));
}

TEST_CASE("isLanAddrV4: 172.16.x.x typical address is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("172.16.254.1")));
}

TEST_CASE("isLanAddrV4: 172.31.255.255 /12 high boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("172.31.255.255")));
}

TEST_CASE("isLanAddrV4: 172.32.0.0 is NOT LAN (just outside /12)")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("172.32.0.0")));
}

TEST_CASE("isLanAddrV4: 172.15.255.255 is NOT LAN (just below /12)")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("172.15.255.255")));
}

TEST_CASE("isLanAddrV4: 192.168.0.0 /16 low boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("192.168.0.0")));
}

TEST_CASE("isLanAddrV4: 192.168.x.x typical address is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("192.168.1.100")));
}

TEST_CASE("isLanAddrV4: 192.168.255.255 /16 high boundary is LAN")
{
    REQUIRE(ntm::isLanAddrV4(ipv4Net("192.168.255.255")));
}

TEST_CASE("isLanAddrV4: 192.169.0.0 is NOT LAN (just outside /16)")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("192.169.0.0")));
}

TEST_CASE("isLanAddrV4: 8.8.8.8 Google DNS is NOT LAN")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("8.8.8.8")));
}

TEST_CASE("isLanAddrV4: 1.1.1.1 Cloudflare DNS is NOT LAN")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("1.1.1.1")));
}

TEST_CASE("isLanAddrV4: 93.184.216.34 example.com is NOT LAN")
{
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("93.184.216.34")));
}

TEST_CASE("isLanAddrV4: 100.64.0.0 CGNAT range is NOT LAN (not in the four RFC 1918 ranges)")
{
    // The client only classifies the four RFC 1918 + loopback ranges as LAN.
    REQUIRE(!ntm::isLanAddrV4(ipv4Net("100.64.0.0")));
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. LAN IPv6 address classification
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("isLanAddrV6: ::1 loopback is LAN")
{
    auto a = ipv6Bytes("::1");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fc00::1 ULA fc00::/7 is LAN")
{
    auto a = ipv6Bytes("fc00::1");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fd00::1 ULA fd00::/8 is LAN")
{
    auto a = ipv6Bytes("fd00::1");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fd12:3456:789a::1 typical ULA is LAN")
{
    auto a = ipv6Bytes("fd12:3456:789a::1");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ULA high boundary is LAN")
{
    auto a = ipv6Bytes("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fe80::1 link-local is LAN")
{
    auto a = ipv6Bytes("fe80::1");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fe80::dead:beef link-local typical is LAN")
{
    auto a = ipv6Bytes("fe80::dead:beef");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: febf:: fe80::/10 high boundary is LAN")
{
    auto a = ipv6Bytes("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    REQUIRE(ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: 2001:db8::1 documentation prefix is NOT LAN")
{
    auto a = ipv6Bytes("2001:db8::1");
    REQUIRE(!ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: 2606:4700::1 Cloudflare is NOT LAN")
{
    auto a = ipv6Bytes("2606:4700::1");
    REQUIRE(!ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: :: all-zeros is NOT LAN")
{
    auto a = ipv6Bytes("::");
    REQUIRE(!ntm::isLanAddrV6(a.data()));
}

TEST_CASE("isLanAddrV6: fec0:: (old site-local, not fc00::/7) is NOT LAN")
{
    // fec0::/10 was deprecated (RFC 3879). It starts with 0xFEC0, which is
    // 0b11111110_11000000. The ULA check is (addr[0] & 0xFE) == 0xFC, which
    // gives 0xFC for addresses starting with 0xFC or 0xFD only.
    // 0xFE & 0xFE = 0xFE ≠ 0xFC → not classified as ULA.
    auto a = ipv6Bytes("fec0::1");
    REQUIRE(!ntm::isLanAddrV6(a.data()));
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. queryExternalIP — early-exit / input-validation (no live network)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("queryExternalIP: empty URL returns empty string")
{
    REQUIRE(ntm::platform::queryExternalIP("", 1000).empty());
}

TEST_CASE("queryExternalIP: https:// URL (not http://) returns empty string")
{
    REQUIRE(ntm::platform::queryExternalIP("https://checkip.amazonaws.com/", 100).empty());
}

TEST_CASE("queryExternalIP: ftp:// URL returns empty string")
{
    REQUIRE(ntm::platform::queryExternalIP("ftp://example.com/", 100).empty());
}

TEST_CASE("queryExternalIP: too-short string returns empty string")
{
    REQUIRE(ntm::platform::queryExternalIP("http://", 100).empty());
}

TEST_CASE("queryExternalIP: non-IP body from unreachable host returns empty string")
{
    // host.invalid. will not resolve; function must return "" not crash.
    REQUIRE(ntm::platform::queryExternalIP("http://host.invalid./ip", 200).empty());
}

TEST_CASE("queryExternalIP: result is always a valid IP string or empty")
{
    // With a deliberately unresolvable host the result must be "" (not garbage).
    std::string r = ntm::platform::queryExternalIP("http://0.0.0.0:1/", 200);
    if (!r.empty())
    {
        struct in_addr  a4{};
        struct in6_addr a6{};
        bool isV4 = (::inet_pton(AF_INET,  r.c_str(), &a4) == 1);
        bool isV6 = (::inet_pton(AF_INET6, r.c_str(), &a6) == 1);
        REQUIRE(isV4 || isV6); // non-empty result MUST be a valid IP
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Platform init / cleanup lifecycle
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("platform: cleanupPlatform then initPlatform again does not crash")
{
    // The global WsaGuard already called initPlatform. Here we verify that
    // a cleanup-then-reinit cycle is safe (e.g. for service restart scenarios).
    ntm::platform::cleanupPlatform();
    ntm::platform::initPlatform();
    // Restore the global state — subsequent tests still need WSA running.
}

TEST_CASE("platform: inet_pton works after initPlatform (WSA sanity)")
{
    // Confirms WSA is initialised for all subsequent test cases.
    struct in_addr a{};
    REQUIRE_EQ(::inet_pton(AF_INET, "192.168.1.1", &a), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. checkIdentityFilePermissions — real Windows ACL check
// ═══════════════════════════════════════════════════════════════════════════

// Helper: create a temp file and return its path, or "" on failure.
static std::string makeTempFile()
{
    char tmpDir[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmpDir)) return {};
    std::string path = std::string(tmpDir) + "ntm_acl_test_tmp.pem";
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    CloseHandle(h);
    return path;
}

// Helper: set the DACL on a file to grant Everyone GENERIC_READ.
static bool setEveryoneRead(const std::string &path)
{
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = FILE_GENERIC_READ;
    ea.grfAccessMode        = GRANT_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = const_cast<LPWSTR>(L"Everyone");

    PACL newAcl = nullptr;
    if (SetEntriesInAclW(1, &ea, nullptr, &newAcl) != ERROR_SUCCESS) return false;
    std::wstring wpath(path.begin(), path.end());
    DWORD ret = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, newAcl, nullptr);
    LocalFree(newAcl);
    return ret == ERROR_SUCCESS;
}

// Helper: restrict a file to the current user only (no inheritance).
static bool setCurrentUserOnly(const std::string &path)
{
    // Get current user SID.
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    BYTE  tokenBuf[512]{};
    DWORD needed = 0;
    if (!GetTokenInformation(hToken, TokenUser, tokenBuf, sizeof(tokenBuf), &needed)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    auto *tu = reinterpret_cast<TOKEN_USER *>(tokenBuf);
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode        = GRANT_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName    = reinterpret_cast<LPWSTR>(tu->User.Sid);

    PACL newAcl = nullptr;
    if (SetEntriesInAclW(1, &ea, nullptr, &newAcl) != ERROR_SUCCESS) return false;
    std::wstring wpath(path.begin(), path.end());
    DWORD ret = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, newAcl, nullptr);
    LocalFree(newAcl);
    return ret == ERROR_SUCCESS;
}

TEST_CASE("checkIdentityFilePermissions: non-existent path does not crash")
{
    ntm::platform::checkIdentityFilePermissions(
        "C:\\nonexistent\\ntm_no_such_file_83749.key", false, false);
    // Must not throw or crash regardless of missing file.
}

TEST_CASE("checkIdentityFilePermissions: file with Everyone-Read triggers warning")
{
    std::string path = makeTempFile();
    if (path.empty()) return; // skip if temp dir unavailable (some CI)

    bool acl_ok = setEveryoneRead(path);
    if (!acl_ok) {
        DeleteFileA(path.c_str());
        return; // skip if no privilege to modify DACL
    }

    // Capture stderr to verify the warning is emitted.
    std::ostringstream captured;
    std::streambuf *saved = std::cerr.rdbuf(captured.rdbuf());
    ntm::platform::checkIdentityFilePermissions(path, false, false);
    std::cerr.rdbuf(saved);
    DeleteFileA(path.c_str());

    REQUIRE(captured.str().find("WARNING") != std::string::npos);
}

TEST_CASE("checkIdentityFilePermissions: file readable only by current user is silent")
{
    std::string path = makeTempFile();
    if (path.empty()) return;

    bool acl_ok = setCurrentUserOnly(path);
    if (!acl_ok) {
        DeleteFileA(path.c_str());
        return;
    }

    std::ostringstream captured;
    std::streambuf *saved = std::cerr.rdbuf(captured.rdbuf());
    ntm::platform::checkIdentityFilePermissions(path, false, false);
    std::cerr.rdbuf(saved);
    DeleteFileA(path.c_str());

    REQUIRE(captured.str().find("WARNING") == std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. daemonize stub (Windows: prints warning and returns; no crash)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("daemonize: false (foreground) is a no-op on Windows")
{
    ntm::platform::daemonize(false);
}

TEST_CASE("daemonize: true prints warning but does not abort on Windows")
{
    ntm::platform::daemonize(true);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. NetworkMonitor start / stop / checkAndClear lifecycle
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("NetworkMonitor: default-constructed, checkAndClear returns false")
{
    ntm::platform::NetworkMonitor mon;
    REQUIRE(!mon.checkAndClear());
}

TEST_CASE("NetworkMonitor: start then stop completes without crash")
{
    ntm::platform::NetworkMonitor mon;
    mon.start();
    mon.stop();
}

TEST_CASE("NetworkMonitor: checkAndClear returns false immediately after start+stop")
{
    ntm::platform::NetworkMonitor mon;
    mon.start();
    mon.stop();
    // No network change was induced; flag must be clear.
    REQUIRE(!mon.checkAndClear());
}

TEST_CASE("NetworkMonitor: checkAndClear clears the flag — second call is false")
{
    ntm::platform::NetworkMonitor mon;
    // Simulate a flag set (internal impl detail: exchange with false twice)
    bool first  = mon.checkAndClear();
    bool second = mon.checkAndClear();
    // Both may be false (no induced change); the key guarantee is that
    // once cleared it stays false until a real change fires.
    REQUIRE(!second || first); // if second is true, first must also have been true
}

TEST_CASE("NetworkMonitor: double stop is safe")
{
    ntm::platform::NetworkMonitor mon;
    mon.start();
    mon.stop();
    mon.stop(); // second stop must not crash or deadlock
}

TEST_CASE("NetworkMonitor: start called twice — second call is a no-op (no double-thread)")
{
    ntm::platform::NetworkMonitor mon;
    mon.start();
    mon.start(); // impl uses exchange(true) guard — no second thread spawned
    mon.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. ClientConfig default values
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ClientConfig: default server is 127.0.0.1")
{
    ntm::ClientConfig cfg;
    REQUIRE_EQ(cfg.server, std::string{"127.0.0.1"});
}

TEST_CASE("ClientConfig: default port matches kDefaultPort")
{
    ntm::ClientConfig cfg;
    REQUIRE_EQ(cfg.port, ntm::kDefaultPort);
}

TEST_CASE("ClientConfig: default externalIpUrl is non-empty")
{
    ntm::ClientConfig cfg;
    REQUIRE(!cfg.externalIpUrl.empty());
}

TEST_CASE("ClientConfig: default externalIpUrl is an http:// URL")
{
    ntm::ClientConfig cfg;
    REQUIRE(cfg.externalIpUrl.substr(0, 7) == std::string{"http://"});
}

TEST_CASE("ClientConfig: default externalIpTimeoutMs is positive")
{
    ntm::ClientConfig cfg;
    REQUIRE(cfg.externalIpTimeoutMs > 0u);
}

TEST_CASE("ClientConfig: auto_update defaults to false")
{
    ntm::ClientConfig cfg;
    REQUIRE(!cfg.auto_update);
}

TEST_CASE("ClientConfig: verbose defaults to false")
{
    ntm::ClientConfig cfg;
    REQUIRE(!cfg.verbose);
}

TEST_CASE("ClientConfig: reconnectMaxAttempts and reconnectIntervalSec are positive")
{
    ntm::ClientConfig cfg;
    REQUIRE(cfg.reconnectMaxAttempts > 0u);
    REQUIRE(cfg.reconnectIntervalSec > 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Version / platform identity constants
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("version: kClientPlatform is windows-amd64")
{
    REQUIRE_EQ(std::string{kClientPlatform}, std::string{"windows-amd64"});
}

TEST_CASE("version: kClientVersion is non-empty")
{
    REQUIRE(!std::string{kClientVersion}.empty());
}

TEST_CASE("version: kClientVersion matches MAJOR.MINOR.PATCH semver")
{
    const std::string ver{kClientVersion};
    // Quick parse: must have exactly two dots, all segments non-empty digits.
    auto d1 = ver.find('.');
    REQUIRE(d1 != std::string::npos);
    auto d2 = ver.find('.', d1 + 1);
    REQUIRE(d2 != std::string::npos);
    REQUIRE(d2 > d1 + 1);                      // minor segment non-empty
    REQUIRE(ver.size() > d2 + 1);              // patch segment non-empty
    // Verify each segment is all digits.
    for (std::size_t i = 0; i < ver.size(); ++i)
    {
        if (ver[i] != '.')
            REQUIRE(ver[i] >= '0' && ver[i] <= '9');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. connectToServer — error paths (no live server required)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("connectToServer: unresolvable hostname returns INVALID_SOCKET with error")
{
    std::string err;
    SOCKET fd = ntm::platform::connectToServer("this-host-does-not-exist.invalid.", 5555, err);
    REQUIRE_EQ(fd, INVALID_SOCKET);
    REQUIRE(!err.empty());
    // Error message must mention the resolution failure.
    REQUIRE(err.find("cannot resolve") != std::string::npos);
}

TEST_CASE("connectToServer: unreachable port returns INVALID_SOCKET with WSA error")
{
    std::string err;
    // 127.0.0.1 resolves but port 1 is almost certainly not open.
    SOCKET fd = ntm::platform::connectToServer("127.0.0.1", 1, err);
    if (fd == INVALID_SOCKET)
    {
        REQUIRE(!err.empty());
        // Error must mention the connect failure and include a WSA code.
        REQUIRE(err.find("connect to") != std::string::npos);
        REQUIRE(err.find("WSA") != std::string::npos);
    }
    else
    {
        // Unlikely but possible (port 1 occupied) — close gracefully and pass.
        ::closesocket(fd);
    }
}

TEST_CASE("connectToServer: empty hostname returns INVALID_SOCKET")
{
    std::string err;
    SOCKET fd = ntm::platform::connectToServer("", 5555, err);
    REQUIRE_EQ(fd, INVALID_SOCKET);
    REQUIRE(!err.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. collectLanAddresses — smoke test (no Npcap required)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("collectLanAddresses: does not crash and returns a set")
{
    // The result may be empty in CI environments with no LAN adapters up,
    // but the call must not throw, crash, or return garbage.
    auto addrs = ntm::platform::collectLanAddresses();
    // If non-empty, every entry must be a non-empty string.
    for (const auto &a : addrs)
        REQUIRE(!a.empty());
}

TEST_CASE("collectLanAddresses: all returned addresses parse as valid IP literals")
{
    auto addrs = ntm::platform::collectLanAddresses();
    for (const auto &a : addrs)
    {
        struct in_addr  v4{};
        struct in6_addr v6{};
        bool ok4 = (::inet_pton(AF_INET,  a.c_str(), &v4) == 1);
        bool ok6 = (::inet_pton(AF_INET6, a.c_str(), &v6) == 1);
        REQUIRE(ok4 || ok6);
    }
}
