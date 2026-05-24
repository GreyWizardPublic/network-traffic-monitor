// tests/test_client_websocket.cpp — unit tests for client_websocket.hpp.
//
// Covers buildClientFrame, buildUpgradeRequest, parseUpgradeResponse, and
// the FrameReader state machine.  All functions are pure logic with no I/O
// — fully testable without a live connection or WSA initialisation.
//
// Run via:  ./build-linux/ntm-tests

#include "ntm_test.hpp"
#include "../src/client_websocket.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace ntm::ws;

// ═══════════════════════════════════════════════════════════════════════════
// buildClientFrame — header layout
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("buildClientFrame: empty payload — 6-byte frame (2 header + 4 mask)")
{
    const std::uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    auto frame = buildClientFrame(nullptr, 0, key);
    // FIN+binary, MASK+len=0, 4-byte mask key
    REQUIRE_EQ(frame.size(), std::size_t{6});
    REQUIRE_EQ(frame[0], std::uint8_t{0x82}); // FIN=1, opcode=2 (binary)
    REQUIRE_EQ(frame[1], std::uint8_t{0x80}); // MASK=1, payload len=0
    REQUIRE_EQ(frame[2], std::uint8_t{0x11});
    REQUIRE_EQ(frame[3], std::uint8_t{0x22});
    REQUIRE_EQ(frame[4], std::uint8_t{0x33});
    REQUIRE_EQ(frame[5], std::uint8_t{0x44});
}

TEST_CASE("buildClientFrame: 1-byte payload — 7-byte frame")
{
    const std::uint8_t key[4]     = {0xAA, 0xBB, 0xCC, 0xDD};
    const std::uint8_t payload[1] = {0xFF};
    auto frame = buildClientFrame(payload, 1, key);
    REQUIRE_EQ(frame.size(), std::size_t{7});
    REQUIRE_EQ(frame[0], std::uint8_t{0x82});
    REQUIRE_EQ(frame[1], std::uint8_t{0x81}); // MASK=1, len=1
    // Masked byte: 0xFF ^ 0xAA = 0x55
    REQUIRE_EQ(frame[6], std::uint8_t{0x55});
}

TEST_CASE("buildClientFrame: 125-byte payload uses 1-byte length")
{
    const std::uint8_t key[4] = {0,0,0,0};
    std::vector<std::uint8_t> payload(125, 0x00);
    auto frame = buildClientFrame(payload.data(), 125, key);
    // 2 header + 4 mask + 125 payload = 131
    REQUIRE_EQ(frame.size(), std::size_t{131});
    REQUIRE_EQ(frame[1], std::uint8_t{0x80 | 125}); // MASK=1, len=125
}

TEST_CASE("buildClientFrame: 126-byte payload uses 16-bit extended length")
{
    const std::uint8_t key[4] = {0,0,0,0};
    std::vector<std::uint8_t> payload(126, 0x00);
    auto frame = buildClientFrame(payload.data(), 126, key);
    // 2 header + 2 ext-len + 4 mask + 126 payload = 134
    REQUIRE_EQ(frame.size(), std::size_t{134});
    REQUIRE_EQ(frame[1], std::uint8_t{0x80 | 126}); // MASK=1, len=126 → use 16-bit
    REQUIRE_EQ(frame[2], std::uint8_t{0x00});        // high byte of 126
    REQUIRE_EQ(frame[3], std::uint8_t{126});         // low byte
}

TEST_CASE("buildClientFrame: 65535-byte payload uses 16-bit extended length")
{
    const std::uint8_t key[4] = {0,0,0,0};
    std::vector<std::uint8_t> payload(65535, 0);
    auto frame = buildClientFrame(payload.data(), 65535, key);
    // 2 + 2 + 4 + 65535 = 65543
    REQUIRE_EQ(frame.size(), std::size_t{65543});
    REQUIRE_EQ(frame[2], std::uint8_t{0xFF});
    REQUIRE_EQ(frame[3], std::uint8_t{0xFF});
}

TEST_CASE("buildClientFrame: masking is applied correctly (XOR with key)")
{
    const std::uint8_t key[4]        = {0x37, 0xFA, 0x21, 0x3D};
    const std::uint8_t payload[4]    = {0x48, 0x65, 0x6C, 0x6C}; // "Hell"
    // expected masked: 0x48^0x37=0x7F, 0x65^0xFA=0x9F, 0x6C^0x21=0x4D, 0x6C^0x3D=0x51
    auto frame = buildClientFrame(payload, 4, key);
    REQUIRE_EQ(frame.size(), std::size_t{10}); // 2+4+4
    REQUIRE_EQ(frame[6], std::uint8_t{0x7F});
    REQUIRE_EQ(frame[7], std::uint8_t{0x9F});
    REQUIRE_EQ(frame[8], std::uint8_t{0x4D});
    REQUIRE_EQ(frame[9], std::uint8_t{0x51});
}

TEST_CASE("buildClientFrame: key cycles every 4 bytes")
{
    const std::uint8_t key[4]     = {0x01, 0x02, 0x03, 0x04};
    const std::uint8_t payload[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
    auto frame = buildClientFrame(payload, 5, key);
    // Masked bytes at indices 6-10 (after 2 hdr + 4 mask)
    REQUIRE_EQ(frame[6], std::uint8_t{0x01}); // payload[0] ^ key[0]
    REQUIRE_EQ(frame[7], std::uint8_t{0x02}); // payload[1] ^ key[1]
    REQUIRE_EQ(frame[8], std::uint8_t{0x03}); // payload[2] ^ key[2]
    REQUIRE_EQ(frame[9], std::uint8_t{0x04}); // payload[3] ^ key[3]
    REQUIRE_EQ(frame[10],std::uint8_t{0x01}); // payload[4] ^ key[4&3=0]
}

// ═══════════════════════════════════════════════════════════════════════════
// buildUpgradeRequest
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("buildUpgradeRequest: contains required HTTP/1.1 headers")
{
    auto req = buildUpgradeRequest("example.com", "dGhlIHNhbXBsZSBub25jZQ==");
    REQUIRE(req.find("GET /ntm-ws HTTP/1.1\r\n") != std::string::npos);
    REQUIRE(req.find("Host: example.com\r\n") != std::string::npos);
    REQUIRE(req.find("Upgrade: websocket\r\n") != std::string::npos);
    REQUIRE(req.find("Connection: Upgrade\r\n") != std::string::npos);
    REQUIRE(req.find("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != std::string::npos);
    REQUIRE(req.find("Sec-WebSocket-Version: 13\r\n") != std::string::npos);
}

TEST_CASE("buildUpgradeRequest: ends with double CRLF")
{
    auto req = buildUpgradeRequest("h", "k");
    REQUIRE(req.size() >= 4);
    REQUIRE_EQ(req.substr(req.size() - 4), std::string{"\r\n\r\n"});
}

// ═══════════════════════════════════════════════════════════════════════════
// parseUpgradeResponse — success cases
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseUpgradeResponse: valid 101 with accept header")
{
    const std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "\r\n";
    std::string accept, err;
    REQUIRE(parseUpgradeResponse(resp, accept, err));
    REQUIRE_EQ(accept, std::string{"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="});
    REQUIRE(err.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// parseUpgradeResponse — failure cases
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("parseUpgradeResponse: wrong status code returns false")
{
    const std::string resp =
        "HTTP/1.1 200 OK\r\n"
        "Sec-WebSocket-Accept: abc\r\n"
        "\r\n";
    std::string accept, err;
    REQUIRE(!parseUpgradeResponse(resp, accept, err));
    REQUIRE(!err.empty());
}

TEST_CASE("parseUpgradeResponse: missing accept header returns false")
{
    const std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "\r\n";
    std::string accept, err;
    REQUIRE(!parseUpgradeResponse(resp, accept, err));
    REQUIRE(err.find("missing") != std::string::npos);
}

TEST_CASE("parseUpgradeResponse: non-HTTP response returns false")
{
    std::string accept, err;
    REQUIRE(!parseUpgradeResponse("garbage data", accept, err));
    REQUIRE(!err.empty());
}

TEST_CASE("parseUpgradeResponse: empty response returns false")
{
    std::string accept, err;
    REQUIRE(!parseUpgradeResponse("", accept, err));
}

// ═══════════════════════════════════════════════════════════════════════════
// FrameReader — single small frame
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("FrameReader: single unmasked binary frame with 3-byte payload")
{
    // Build a server→client unmasked binary frame manually:
    // byte0: FIN=1, opcode=2 → 0x82
    // byte1: MASK=0, len=3   → 0x03
    // payload: 0x01 0x02 0x03
    const std::uint8_t frame[] = {0x82, 0x03, 0x01, 0x02, 0x03};
    FrameReader reader;
    reader.feed(frame, sizeof(frame));

    REQUIRE_EQ(reader.available(), std::size_t{3});
    std::uint8_t out[3] = {};
    REQUIRE_EQ(reader.take(out, 3), std::size_t{3});
    REQUIRE_EQ(out[0], std::uint8_t{0x01});
    REQUIRE_EQ(out[1], std::uint8_t{0x02});
    REQUIRE_EQ(out[2], std::uint8_t{0x03});
    REQUIRE_EQ(reader.available(), std::size_t{0});
}

TEST_CASE("FrameReader: byte-by-byte feeding produces the same result")
{
    const std::uint8_t frame[] = {0x82, 0x02, 0xAA, 0xBB};
    FrameReader reader;
    for (auto b : frame)
        reader.feed(&b, 1);

    REQUIRE_EQ(reader.available(), std::size_t{2});
    std::uint8_t out[2] = {};
    reader.take(out, 2);
    REQUIRE_EQ(out[0], std::uint8_t{0xAA});
    REQUIRE_EQ(out[1], std::uint8_t{0xBB});
}

TEST_CASE("FrameReader: two consecutive frames are both consumed")
{
    // Frame 1: FIN=1, binary, len=1, payload=0x10
    // Frame 2: FIN=1, binary, len=1, payload=0x20
    const std::uint8_t frames[] = {0x82, 0x01, 0x10,
                                   0x82, 0x01, 0x20};
    FrameReader reader;
    reader.feed(frames, sizeof(frames));

    REQUIRE_EQ(reader.available(), std::size_t{2});
    std::uint8_t out[2] = {};
    reader.take(out, 2);
    REQUIRE_EQ(out[0], std::uint8_t{0x10});
    REQUIRE_EQ(out[1], std::uint8_t{0x20});
}

TEST_CASE("FrameReader: control frame (ping) payload is discarded")
{
    // Ping frame: FIN=1, opcode=0x9, len=2, payload=0xDE 0xAD
    const std::uint8_t ping[] = {0x89, 0x02, 0xDE, 0xAD};
    FrameReader reader;
    reader.feed(ping, sizeof(ping));
    // Ping payload must NOT appear in the read buffer
    REQUIRE_EQ(reader.available(), std::size_t{0});
}

TEST_CASE("FrameReader: close frame payload is discarded")
{
    const std::uint8_t close[] = {0x88, 0x02, 0x03, 0xE8}; // status 1000
    FrameReader reader;
    reader.feed(close, sizeof(close));
    REQUIRE_EQ(reader.available(), std::size_t{0});
}

TEST_CASE("FrameReader: 16-bit extended length frame")
{
    // FIN=1, binary, 16-bit len=300
    // byte0=0x82, byte1=0x7E, byte2=0x01, byte3=0x2C, then 300 payload bytes
    std::vector<std::uint8_t> frame;
    frame.push_back(0x82);
    frame.push_back(0x7E);      // 126 → use 16-bit extension
    frame.push_back(0x01);      // hi byte of 300
    frame.push_back(0x2C);      // lo byte of 300
    for (int i = 0; i < 300; ++i)
        frame.push_back(static_cast<std::uint8_t>(i & 0xFF));

    FrameReader reader;
    reader.feed(frame.data(), frame.size());
    REQUIRE_EQ(reader.available(), std::size_t{300});

    std::vector<std::uint8_t> out(300);
    REQUIRE_EQ(reader.take(out.data(), 300), std::size_t{300});
    for (int i = 0; i < 300; ++i)
        REQUIRE_EQ(out[static_cast<std::size_t>(i)],
                   static_cast<std::uint8_t>(i & 0xFF));
}

TEST_CASE("FrameReader: empty binary frame (len=0) is silently consumed")
{
    // FIN=1, binary, len=0
    const std::uint8_t frame[] = {0x82, 0x00};
    FrameReader reader;
    reader.feed(frame, sizeof(frame));
    REQUIRE_EQ(reader.available(), std::size_t{0});
}

TEST_CASE("FrameReader: take() partial read returns correct count")
{
    const std::uint8_t frame[] = {0x82, 0x04, 0x01, 0x02, 0x03, 0x04};
    FrameReader reader;
    reader.feed(frame, sizeof(frame));

    std::uint8_t out[2] = {};
    std::size_t got = reader.take(out, 2);
    REQUIRE_EQ(got, std::size_t{2});
    REQUIRE_EQ(reader.available(), std::size_t{2}); // 2 bytes remaining
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket constants
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ws constants: kWsPath is /ntm-ws")
{
    REQUIRE_EQ(std::string{kWsPath}, std::string{"/ntm-ws"});
}

TEST_CASE("ws constants: kWsVersion is 13")
{
    REQUIRE_EQ(kWsVersion, 13);
}

TEST_CASE("ws constants: opcode values match RFC 6455")
{
    REQUIRE_EQ(kOpcodeContinuation, std::uint8_t{0x0});
    REQUIRE_EQ(kOpcodeBinary,       std::uint8_t{0x2});
    REQUIRE_EQ(kOpcodeClose,        std::uint8_t{0x8});
    REQUIRE_EQ(kOpcodePing,         std::uint8_t{0x9});
    REQUIRE_EQ(kOpcodePong,         std::uint8_t{0xA});
}
