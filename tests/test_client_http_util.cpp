// tests/test_client_http_util.cpp — unit tests for client_http_util.hpp.
//
// All three helpers (parseHttpUrl, extractHttpBody, buildGetRequest) are pure
// logic — no syscalls, no network — so they are fully testable here.
//
// Run via:  ./build-linux/ntm-tests

#include "ntm_test.hpp"
#include "../src/client_http_util.hpp"

using namespace ntm::http_util;

// ═══════════════════════════════════════════════════════════════════════════
// parseHttpUrl — happy paths
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHttpUrl: plain host with default port")
{
    auto r = parseHttpUrl("http://example.com/");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.host, std::string{"example.com"});
    REQUIRE_EQ(r.port, std::string{"80"});
    REQUIRE_EQ(r.path, std::string{"/"});
}

TEST_CASE("parseHttpUrl: host with explicit port")
{
    auto r = parseHttpUrl("http://myserver.local:9090/api/ip");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.host, std::string{"myserver.local"});
    REQUIRE_EQ(r.port, std::string{"9090"});
    REQUIRE_EQ(r.path, std::string{"/api/ip"});
}

TEST_CASE("parseHttpUrl: host with no path — path defaults to /")
{
    auto r = parseHttpUrl("http://checkip.amazonaws.com");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.host, std::string{"checkip.amazonaws.com"});
    REQUIRE_EQ(r.port, std::string{"80"});
    REQUIRE_EQ(r.path, std::string{"/"});
}

TEST_CASE("parseHttpUrl: IPv4 literal host")
{
    auto r = parseHttpUrl("http://192.168.1.1:8080/check");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.host, std::string{"192.168.1.1"});
    REQUIRE_EQ(r.port, std::string{"8080"});
    REQUIRE_EQ(r.path, std::string{"/check"});
}

TEST_CASE("parseHttpUrl: path with multiple segments")
{
    auto r = parseHttpUrl("http://example.com/some/long/path");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.path, std::string{"/some/long/path"});
}

TEST_CASE("parseHttpUrl: well-known external IP checker URL")
{
    auto r = parseHttpUrl("http://checkip.amazonaws.com/");
    REQUIRE(r.ok);
    REQUIRE_EQ(r.host, std::string{"checkip.amazonaws.com"});
    REQUIRE_EQ(r.port, std::string{"80"});
    REQUIRE_EQ(r.path, std::string{"/"});
}

// ═══════════════════════════════════════════════════════════════════════════
// parseHttpUrl — rejection cases
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseHttpUrl: https:// is rejected (not http)")
{
    auto r = parseHttpUrl("https://example.com/");
    REQUIRE(!r.ok);
}

TEST_CASE("parseHttpUrl: ftp:// is rejected")
{
    auto r = parseHttpUrl("ftp://example.com/");
    REQUIRE(!r.ok);
}

TEST_CASE("parseHttpUrl: empty string is rejected")
{
    auto r = parseHttpUrl("");
    REQUIRE(!r.ok);
}

TEST_CASE("parseHttpUrl: bare http:// (no host) is rejected")
{
    auto r = parseHttpUrl("http://");
    REQUIRE(!r.ok);
}

TEST_CASE("parseHttpUrl: no scheme is rejected")
{
    auto r = parseHttpUrl("example.com/");
    REQUIRE(!r.ok);
}

// ═══════════════════════════════════════════════════════════════════════════
// extractHttpBody — happy paths
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("extractHttpBody: simple HTTP/1.0 response with plain-text body")
{
    std::string resp =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "203.0.113.42";
    REQUIRE_EQ(extractHttpBody(resp), std::string{"203.0.113.42"});
}

TEST_CASE("extractHttpBody: body with trailing CRLF is stripped")
{
    std::string resp =
        "HTTP/1.0 200 OK\r\n"
        "\r\n"
        "1.2.3.4\r\n";
    REQUIRE_EQ(extractHttpBody(resp), std::string{"1.2.3.4"});
}

TEST_CASE("extractHttpBody: body with leading whitespace is stripped")
{
    std::string resp =
        "HTTP/1.0 200 OK\r\n"
        "\r\n"
        "  5.6.7.8";
    REQUIRE_EQ(extractHttpBody(resp), std::string{"5.6.7.8"});
}

TEST_CASE("extractHttpBody: short hex chunk-size line is removed")
{
    // Some HTTP/1.0 servers send a hex length line before the body.
    std::string resp =
        "HTTP/1.0 200 OK\r\n"
        "\r\n"
        "b\n"           // hex '11' — short line <= 7 chars gets removed
        "1.2.3.4\r\n";
    REQUIRE_EQ(extractHttpBody(resp), std::string{"1.2.3.4"});
}

TEST_CASE("extractHttpBody: body with only whitespace returns empty")
{
    std::string resp = "HTTP/1.0 200 OK\r\n\r\n   \r\n\t\r\n";
    REQUIRE_EQ(extractHttpBody(resp), std::string{});
}

// ═══════════════════════════════════════════════════════════════════════════
// extractHttpBody — missing separator
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("extractHttpBody: missing CRLFCRLF separator returns empty")
{
    REQUIRE_EQ(extractHttpBody("HTTP/1.0 200 OK\r\nno separator here"), std::string{});
}

TEST_CASE("extractHttpBody: empty string returns empty")
{
    REQUIRE_EQ(extractHttpBody(""), std::string{});
}

// ═══════════════════════════════════════════════════════════════════════════
// buildGetRequest
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("buildGetRequest: standard / path")
{
    auto req = buildGetRequest("/", "checkip.amazonaws.com");
    REQUIRE_EQ(req, std::string{
        "GET / HTTP/1.0\r\n"
        "Host: checkip.amazonaws.com\r\n"
        "Connection: close\r\n"
        "\r\n"
    });
}

TEST_CASE("buildGetRequest: sub-path")
{
    auto req = buildGetRequest("/api/ip", "example.com");
    REQUIRE_EQ(req, std::string{
        "GET /api/ip HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n"
        "\r\n"
    });
}

TEST_CASE("buildGetRequest: ends with double CRLF")
{
    auto req = buildGetRequest("/", "h");
    REQUIRE(req.size() >= 4);
    REQUIRE_EQ(req.substr(req.size() - 4), std::string{"\r\n\r\n"});
}

// ═══════════════════════════════════════════════════════════════════════════
// hasValidHostname — L-2 host-header injection guard
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("hasValidHostname: plain hostname is valid")
{
    REQUIRE(hasValidHostname("ntm.example.com"));
}

TEST_CASE("hasValidHostname: IP address is valid")
{
    REQUIRE(hasValidHostname("192.168.1.1"));
}

TEST_CASE("hasValidHostname: hostname with port suffix is valid")
{
    REQUIRE(hasValidHostname("server.local:8443"));
}

TEST_CASE("hasValidHostname: empty string is valid (caller responsibility)")
{
    REQUIRE(hasValidHostname(""));
}

TEST_CASE("hasValidHostname: CR injection is rejected (L-2)")
{
    REQUIRE(!hasValidHostname("victim.com\r\nX-Injected: evil"));
}

TEST_CASE("hasValidHostname: LF injection is rejected (L-2)")
{
    REQUIRE(!hasValidHostname("victim.com\nX-Injected: evil"));
}

TEST_CASE("hasValidHostname: bare CR is rejected")
{
    REQUIRE(!hasValidHostname("host\r"));
}

// ═══════════════════════════════════════════════════════════════════════════
// jsonStr — L-1 JSON escape handling
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("jsonStr: plain string value extracted correctly")
{
    REQUIRE_EQ(jsonStr(R"({"version":"1.2.3"})", "version"),
               std::string{"1.2.3"});
}

TEST_CASE("jsonStr: sha256 hex value extracted correctly")
{
    std::string hash(64, 'a');
    std::string json = R"({"sha256":")" + hash + R"("})";
    REQUIRE_EQ(jsonStr(json, "sha256"), hash);
}

TEST_CASE("jsonStr: escaped quote inside value is not treated as terminator (L-1)")
{
    // {"version":"1.2\"hack"} — the \" is an escaped quote inside the string,
    // not the closing quote.
    REQUIRE_EQ(jsonStr(R"({"version":"1.2\"hack"})", "version"),
               std::string{R"(1.2"hack)"});
}

TEST_CASE("jsonStr: backslash escape folds next char (backslash-n becomes 'n', not newline)")
{
    // The extractor consumes the backslash and keeps the next character as-is;
    // \n becomes the letter 'n', not a newline byte.
    REQUIRE_EQ(jsonStr(R"({"v":"a\nb"})", "v"), std::string{"anb"});
}

TEST_CASE("jsonStr: missing key returns empty string")
{
    REQUIRE_EQ(jsonStr(R"({"other":"x"})", "version"), std::string{});
}

TEST_CASE("jsonStr: empty JSON returns empty string")
{
    REQUIRE_EQ(jsonStr("", "version"), std::string{});
}

TEST_CASE("jsonStr: unterminated value returns empty string")
{
    // The closing '"' is never found — should return {} rather than partial.
    REQUIRE_EQ(jsonStr(R"({"version":"1.2.3)", "version"), std::string{});
}

TEST_CASE("jsonStr: value adjacent to other fields is not confused")
{
    REQUIRE_EQ(jsonStr(R"({"a":"x","version":"1.9.0","b":"y"})", "version"),
               std::string{"1.9.0"});
}
