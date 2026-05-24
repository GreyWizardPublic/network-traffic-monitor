// tests/test_client_config.cpp — unit tests for loadClientConfig() / parseConfigLine().
//
// parseConfigLine is a static function in client_core.cpp so it cannot be
// called directly from the test binary.  All tests go through loadClientConfig()
// which exercises the same parsing paths using small temp files.
//
// Run via:  ./build-linux/ntm-tests

#include "ntm_test.hpp"
#include "../src/client_config_parse.hpp"  // parseConfigLine, loadClientConfig (inline)
#include "../src/proto_client_server.hpp"  // kDefaultPort

#include <cstdio>
#include <fstream>
#include <string>

// Helper: write a config file to a temp path and load it.
// Returns false if the file could not be written.
static bool writeAndLoad(const std::string &contents, ntm::ClientConfig &out)
{
    // Use a fixed path under /tmp — the test binary is single-threaded.
    const std::string path = "/tmp/ntm_test_config.conf";
    {
        std::ofstream f(path, std::ios::trunc);
        if (!f) return false;
        f << contents;
    }
    bool ok = ntm::loadClientConfig(path, out);
    std::remove(path.c_str());
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════════
// File presence / defaults
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: missing file returns false")
{
    ntm::ClientConfig cfg;
    REQUIRE(!ntm::loadClientConfig("/tmp/ntm_no_such_file_39271.conf", cfg));
}

TEST_CASE("loadClientConfig: empty config file returns true with default values")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("", cfg));
    REQUIRE_EQ(cfg.server, std::string{"127.0.0.1"});
    REQUIRE_EQ(cfg.port, ntm::kDefaultPort);
    REQUIRE(cfg.useCompression);
    REQUIRE(cfg.transport == ntm::TransportMode::TcpTls);
}

// ═══════════════════════════════════════════════════════════════════════════
// Basic key=value parsing
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: server= is parsed")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("server=my.ntm-server.example\n", cfg));
    REQUIRE_EQ(cfg.server, std::string{"my.ntm-server.example"});
}

TEST_CASE("loadClientConfig: port= sets the port")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("port=9443\n", cfg));
    REQUIRE_EQ(cfg.port, std::uint16_t{9443});
}

TEST_CASE("loadClientConfig: invalid port is ignored (keeps default)")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("port=notanumber\n", cfg));
    REQUIRE_EQ(cfg.port, ntm::kDefaultPort);
}

TEST_CASE("loadClientConfig: out-of-range port 0 is ignored")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("port=0\n", cfg));
    REQUIRE_EQ(cfg.port, ntm::kDefaultPort);
}

TEST_CASE("loadClientConfig: out-of-range port 65536 is ignored")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("port=65536\n", cfg));
    REQUIRE_EQ(cfg.port, ntm::kDefaultPort);
}

TEST_CASE("loadClientConfig: identity= sets identityPath")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("identity=/etc/ntm/client.pem\n", cfg));
    REQUIRE_EQ(cfg.identityPath, std::string{"/etc/ntm/client.pem"});
}

TEST_CASE("loadClientConfig: ca= sets tlsCaPath")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("ca=/etc/ssl/certs/ca-bundle.crt\n", cfg));
    REQUIRE_EQ(cfg.tlsCaPath, std::string{"/etc/ssl/certs/ca-bundle.crt"});
}

TEST_CASE("loadClientConfig: server_cert= sets tlsServerCertPath")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("server_cert=/etc/ntm/server.pem\n", cfg));
    REQUIRE_EQ(cfg.tlsServerCertPath, std::string{"/etc/ntm/server.pem"});
}

// ═══════════════════════════════════════════════════════════════════════════
// Comment and whitespace handling
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: # lines are ignored")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad(
        "# This is a comment\n"
        "server=real.server.com\n"
        "# another comment\n",
        cfg));
    REQUIRE_EQ(cfg.server, std::string{"real.server.com"});
}

TEST_CASE("loadClientConfig: blank lines are ignored")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("\n\n\nserver=s.example\n\n", cfg));
    REQUIRE_EQ(cfg.server, std::string{"s.example"});
}

TEST_CASE("loadClientConfig: last definition wins for repeated keys")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("server=first\nserver=second\n", cfg));
    REQUIRE_EQ(cfg.server, std::string{"second"});
}

// ═══════════════════════════════════════════════════════════════════════════
// Boolean keys
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: verbose=true sets verbose")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("verbose=true\n", cfg));
    REQUIRE(cfg.verbose);
}

TEST_CASE("loadClientConfig: verbose=1 sets verbose")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("verbose=1\n", cfg));
    REQUIRE(cfg.verbose);
}

TEST_CASE("loadClientConfig: verbose=false clears verbose")
{
    ntm::ClientConfig cfg;
    cfg.verbose = true;
    REQUIRE(writeAndLoad("verbose=false\n", cfg));
    REQUIRE(!cfg.verbose);
}

// ═══════════════════════════════════════════════════════════════════════════
// compress= key
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: compress=false disables compression")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("compress=false\n", cfg));
    REQUIRE(!cfg.useCompression);
}

TEST_CASE("loadClientConfig: compress=0 disables compression")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("compress=0\n", cfg));
    REQUIRE(!cfg.useCompression);
}

TEST_CASE("loadClientConfig: compress=no disables compression")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("compress=no\n", cfg));
    REQUIRE(!cfg.useCompression);
}

TEST_CASE("loadClientConfig: compress=true enables compression (default)")
{
    ntm::ClientConfig cfg;
    cfg.useCompression = false;  // override default
    REQUIRE(writeAndLoad("compress=true\n", cfg));
    REQUIRE(cfg.useCompression);
}

// ═══════════════════════════════════════════════════════════════════════════
// transport= key
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: transport=websocket sets WebSocket mode")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("transport=websocket\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::WebSocket);
}

TEST_CASE("loadClientConfig: transport=ws sets WebSocket mode (alias)")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("transport=ws\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::WebSocket);
}

TEST_CASE("loadClientConfig: transport=WebSocket (mixed case) sets WebSocket mode")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("transport=WebSocket\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::WebSocket);
}

TEST_CASE("loadClientConfig: transport=tcp sets TcpTls mode")
{
    ntm::ClientConfig cfg;
    cfg.transport = ntm::TransportMode::WebSocket; // pre-set to non-default
    REQUIRE(writeAndLoad("transport=tcp\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::TcpTls);
}

TEST_CASE("loadClientConfig: transport= default (no key) is TcpTls")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("server=s\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::TcpTls);
}

TEST_CASE("loadClientConfig: transport= unknown value falls back to TcpTls")
{
    ntm::ClientConfig cfg;
    // Any unrecognised value should map to TcpTls (the safe default)
    REQUIRE(writeAndLoad("transport=quic\n", cfg));
    REQUIRE(cfg.transport == ntm::TransportMode::TcpTls);
}

// ═══════════════════════════════════════════════════════════════════════════
// reconnect keys
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: reconnect_attempts= sets reconnectMaxAttempts")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("reconnect_attempts=5\n", cfg));
    REQUIRE_EQ(cfg.reconnectMaxAttempts, 5u);
}

TEST_CASE("loadClientConfig: reconnect_interval_sec= sets reconnectIntervalSec")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad("reconnect_interval_sec=120\n", cfg));
    REQUIRE_EQ(cfg.reconnectIntervalSec, 120u);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple keys in one file
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("loadClientConfig: multiple keys are all applied")
{
    ntm::ClientConfig cfg;
    REQUIRE(writeAndLoad(
        "# ntm-client config\n"
        "server=cf.example.com\n"
        "port=443\n"
        "transport=websocket\n"
        "compress=false\n"
        "reconnect_attempts=3\n",
        cfg));
    REQUIRE_EQ(cfg.server, std::string{"cf.example.com"});
    REQUIRE_EQ(cfg.port, std::uint16_t{443});
    REQUIRE(cfg.transport == ntm::TransportMode::WebSocket);
    REQUIRE(!cfg.useCompression);
    REQUIRE_EQ(cfg.reconnectMaxAttempts, 3u);
}
