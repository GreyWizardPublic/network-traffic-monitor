// tests/test_alpn.cpp — unit tests for ntm::selectAlpnFromClientList()
// No OpenSSL dependency — the function is pure C++ in proto_client_server.hpp.
// Run via ntm-tests binary (CTest: cmake --build build-linux --target ntm-tests).

#include "ntm_test.hpp"
#include "../src/proto_client_server.hpp"

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helper: build an OpenSSL wire-format ALPN list from a vector of strings.
// Wire format: each protocol is a 1-byte length prefix followed by the bytes.
// ---------------------------------------------------------------------------
static std::vector<unsigned char> buildAlpnList(const std::vector<std::string> &protocols)
{
    std::vector<unsigned char> out;
    for (const auto &p : protocols)
    {
        out.push_back(static_cast<unsigned char>(p.size()));
        for (char c : p)
            out.push_back(static_cast<unsigned char>(c));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("selectAlpnFromClientList: ntm-wire only → selects ntm-wire")
{
    auto buf = buildAlpnList({"ntm-wire"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnNtmWire});
}

TEST_CASE("selectAlpnFromClientList: http/1.1 only → selects http/1.1")
{
    auto buf = buildAlpnList({"http/1.1"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnHttp11});
}

TEST_CASE("selectAlpnFromClientList: ntm-wire beats http/1.1 (ntm-wire second)")
{
    // ntm-wire has higher priority even when listed after http/1.1.
    auto buf = buildAlpnList({"http/1.1", "ntm-wire"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnNtmWire});
}

TEST_CASE("selectAlpnFromClientList: ntm-wire beats http/1.1 (ntm-wire first)")
{
    auto buf = buildAlpnList({"ntm-wire", "http/1.1"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnNtmWire});
}

TEST_CASE("selectAlpnFromClientList: empty list → http/1.1 fallback")
{
    // nullptr / 0 length simulates a client with no ALPN extension (older browsers).
    auto result = ntm::selectAlpnFromClientList(nullptr, 0);
    REQUIRE_EQ(result, std::string{ntm::kAlpnHttp11});
}

TEST_CASE("selectAlpnFromClientList: unknown protocols only → http/1.1 fallback")
{
    auto buf = buildAlpnList({"h2", "spdy/3.1"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnHttp11});
}

TEST_CASE("selectAlpnFromClientList: ntm-wire buried among many protocols")
{
    auto buf = buildAlpnList({"h2", "http/1.1", "ntm-wire", "spdy/3.1"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnNtmWire});
}

TEST_CASE("selectAlpnFromClientList: truncated length field handled safely")
{
    // Valid "http/1.1" followed by a length byte claiming 255 more bytes (truncated).
    auto buf = buildAlpnList({"http/1.1"});
    buf.push_back(0xFF); // malformed: length 255 but no following bytes
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    // Must have found "http/1.1" before the bad entry; must not crash or read OOB.
    REQUIRE_EQ(result, std::string{ntm::kAlpnHttp11});
}

TEST_CASE("selectAlpnFromClientList: wire encoding length is 1 + strlen")
{
    // Sanity-check the wire encoding so tests that rely on its size are correct.
    auto buf = buildAlpnList({"ntm-wire"});
    // 1 length byte + 8 chars of "ntm-wire" = 9 bytes.
    REQUIRE_EQ(buf.size(), std::size_t{9});
}

TEST_CASE("selectAlpnFromClientList: http/1.1 selected when ntm-wire absent")
{
    // Offers http/1.1 and something unknown but NOT ntm-wire → should pick http/1.1.
    auto buf = buildAlpnList({"h2", "http/1.1"});
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnHttp11});
}

TEST_CASE("selectAlpnFromClientList: zero-length entry in list handled safely")
{
    // A zero-length entry is technically invalid but must not cause infinite loop.
    std::vector<unsigned char> buf;
    buf.push_back(0); // zero-length protocol entry
    buf.push_back(8); // then "ntm-wire"
    for (char c : std::string{"ntm-wire"}) buf.push_back(static_cast<unsigned char>(c));
    // Zero-length won't match "ntm-wire" (len==8 check); ntm-wire entry should match.
    auto result = ntm::selectAlpnFromClientList(buf.data(), static_cast<unsigned>(buf.size()));
    REQUIRE_EQ(result, std::string{ntm::kAlpnNtmWire});
}
