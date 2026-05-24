#pragma once

// client_websocket.hpp — RFC 6455 WebSocket framing helpers for ntm-client.
//
// ALL functions here are pure logic: no I/O, no platform syscalls, no OpenSSL.
// This makes the frame building and parsing fully testable without a live
// connection or WSA initialisation.
//
// OpenSSL-dependent operations (SHA-1 for accept-key computation, RAND_bytes
// for mask-key generation) live in client_transport_websocket.cpp.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ntm::ws
{

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// The well-known GUID appended to Sec-WebSocket-Key before SHA-1 hashing.
inline constexpr const char kWsGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// URL path the ntm-client uses for the WebSocket upgrade.
inline constexpr const char kWsPath[] = "/ntm-ws";

// Required WebSocket protocol version (RFC 6455).
inline constexpr int kWsVersion = 13;

// RFC 6455 opcodes used by ntm-wire.
inline constexpr std::uint8_t kOpcodeContinuation = 0x0;
inline constexpr std::uint8_t kOpcodeBinary       = 0x2;
inline constexpr std::uint8_t kOpcodeClose        = 0x8;
inline constexpr std::uint8_t kOpcodePing         = 0x9;
inline constexpr std::uint8_t kOpcodePong         = 0xA;

// ---------------------------------------------------------------------------
// Client → server frame building (masking required per RFC 6455 §5.3)
// ---------------------------------------------------------------------------

// Build a single RFC 6455 binary data frame for client→server use.
// maskKey must be exactly 4 bytes (caller provides entropy).
// The returned buffer is ready to write directly to the wire.
inline std::vector<std::uint8_t> buildClientFrame(
    const void *payload, std::size_t payloadLen,
    const std::uint8_t maskKey[4])
{
    std::vector<std::uint8_t> frame;

    // Byte 0: FIN=1, RSV=0, opcode=binary(2)
    frame.push_back(0x80u | kOpcodeBinary);

    // Byte 1: MASK=1, payload length
    if (payloadLen < 126)
    {
        frame.push_back(static_cast<std::uint8_t>(0x80u | payloadLen));
    }
    else if (payloadLen <= 0xFFFF)
    {
        frame.push_back(0x80u | 126u);
        frame.push_back(static_cast<std::uint8_t>((payloadLen >> 8) & 0xFF));
        frame.push_back(static_cast<std::uint8_t>( payloadLen       & 0xFF));
    }
    else
    {
        frame.push_back(0x80u | 127u);
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<std::uint8_t>(
                (payloadLen >> (8 * i)) & 0xFF));
    }

    // Masking key
    frame.push_back(maskKey[0]);
    frame.push_back(maskKey[1]);
    frame.push_back(maskKey[2]);
    frame.push_back(maskKey[3]);

    // Masked payload
    const auto *src = static_cast<const std::uint8_t *>(payload);
    for (std::size_t i = 0; i < payloadLen; ++i)
        frame.push_back(src[i] ^ maskKey[i & 3]);

    return frame;
}

// ---------------------------------------------------------------------------
// HTTP upgrade request building (pure string operations)
// ---------------------------------------------------------------------------

// Build the HTTP/1.1 upgrade request to send to the server.
// key should be a base64-encoded 16-byte random value (Sec-WebSocket-Key).
inline std::string buildUpgradeRequest(const std::string &host,
                                        const std::string &key)
{
    return std::string("GET ") + kWsPath + " HTTP/1.1\r\n"
           "Host: " + host + "\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: " + key + "\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n";
}

// ---------------------------------------------------------------------------
// HTTP upgrade response parsing (pure string operations)
// ---------------------------------------------------------------------------

// Parse the server's HTTP 101 response and extract the Sec-WebSocket-Accept
// header value.  Returns true if status is "101" and the accept header is
// present; errOut describes the failure otherwise.
// acceptOut is populated on success.
inline bool parseUpgradeResponse(const std::string &response,
                                  std::string       &acceptOut,
                                  std::string       &errOut)
{
    // Status line must be "HTTP/1.1 101 ..."
    if (response.size() < 12 ||
        response.substr(0, 9) != "HTTP/1.1 ")
    {
        errOut = "not an HTTP/1.1 response";
        return false;
    }
    if (response.substr(9, 3) != "101")
    {
        auto end = response.find('\r');
        errOut = "expected 101, got: " + response.substr(0, end);
        return false;
    }

    // Find Sec-WebSocket-Accept header (case-insensitive name match not
    // needed for RFC 6455 compliance — servers must use this exact casing).
    const std::string kAcceptHdr = "Sec-WebSocket-Accept: ";
    auto pos = response.find(kAcceptHdr);
    if (pos == std::string::npos)
    {
        errOut = "Sec-WebSocket-Accept header missing";
        return false;
    }
    pos += kAcceptHdr.size();
    auto end = response.find('\r', pos);
    acceptOut = response.substr(pos, end - pos);
    return true;
}

// ---------------------------------------------------------------------------
// Server → client frame reader (stateful, no I/O)
// ---------------------------------------------------------------------------

// RFC 6455 frame parser for server-to-client frames (server MUST NOT mask).
// Usage:
//   FrameReader reader;
//   reader.feed(data, n);      // feed bytes from the network
//   while (reader.available()) // consume payload
//       reader.take(dst, n);
class FrameReader
{
public:
    // Feed n bytes into the parser.  Data is buffered internally; the parser
    // extracts payload bytes from completed frames.
    void feed(const std::uint8_t *data, std::size_t n)
    {
        for (std::size_t i = 0; i < n; ++i)
            processByte(data[i]);
    }

    // Number of payload bytes buffered and ready to read.
    std::size_t available() const { return buf_.size() - readPos_; }

    // Copy up to n payload bytes into dst.  Returns the number actually copied.
    std::size_t take(std::uint8_t *dst, std::size_t n)
    {
        std::size_t avail = available();
        std::size_t got   = (n < avail) ? n : avail;
        if (got > 0)
        {
            std::memcpy(dst, buf_.data() + readPos_, got);
            readPos_ += got;
        }
        // Compact buffer when half is consumed to prevent unbounded growth.
        if (readPos_ >= buf_.size() / 2 && readPos_ > 0)
        {
            buf_.erase(buf_.begin(),
                       buf_.begin() + static_cast<std::ptrdiff_t>(readPos_));
            readPos_ = 0;
        }
        return got;
    }

private:
    // Parser state machine
    enum class State : std::uint8_t
    {
        Byte0,          // waiting for first frame byte (FIN + opcode)
        Byte1,          // waiting for second frame byte (mask + length)
        ExtLen16_Hi,    // 2-byte extended length, high byte
        ExtLen16_Lo,    // 2-byte extended length, low byte
        ExtLen64,       // 8-byte extended length
        Payload         // payload bytes
    };

    State         state_{State::Byte0};
    std::uint8_t  opcode_{0};
    bool          fin_{false};
    std::uint64_t payloadLen_{0};
    std::uint64_t extLenBytesRead_{0};
    std::uint64_t payloadBytesRead_{0};

    std::vector<std::uint8_t> buf_;      // assembled payload ready to read
    std::size_t               readPos_{0};

    // Include <cstring> for memcpy when used as a standalone header in tests.
    // client_transport_websocket.cpp includes it anyway.
    static void memcpy_wrap(void *d, const void *s, std::size_t n)
    {
        std::memcpy(d, s, n);
    }

    void processByte(std::uint8_t b)
    {
        switch (state_)
        {
        case State::Byte0:
            fin_     = (b & 0x80u) != 0;
            opcode_  = b & 0x0Fu;
            state_   = State::Byte1;
            break;

        case State::Byte1:
        {
            // MASK bit: server→client frames MUST NOT be masked; we ignore it.
            std::uint8_t len7 = b & 0x7Fu;
            if (len7 < 126)
            {
                payloadLen_       = len7;
                payloadBytesRead_ = 0;
                state_ = (payloadLen_ == 0) ? State::Byte0 : State::Payload;
            }
            else if (len7 == 126)
            {
                payloadLen_       = 0;
                extLenBytesRead_  = 0;
                state_ = State::ExtLen16_Hi;
            }
            else // 127
            {
                payloadLen_       = 0;
                extLenBytesRead_  = 0;
                state_ = State::ExtLen64;
            }
            break;
        }

        case State::ExtLen16_Hi:
            payloadLen_ = static_cast<std::uint64_t>(b) << 8;
            state_      = State::ExtLen16_Lo;
            break;

        case State::ExtLen16_Lo:
            payloadLen_      |= b;
            payloadBytesRead_ = 0;
            state_ = (payloadLen_ == 0) ? State::Byte0 : State::Payload;
            break;

        case State::ExtLen64:
            payloadLen_ = (payloadLen_ << 8) | b;
            if (++extLenBytesRead_ == 8)
            {
                payloadBytesRead_ = 0;
                state_ = (payloadLen_ == 0) ? State::Byte0 : State::Payload;
            }
            break;

        case State::Payload:
            // Accumulate payload only for binary/continuation frames;
            // discard ping/pong/close frames silently.
            if (opcode_ == kOpcodeBinary || opcode_ == kOpcodeContinuation)
                buf_.push_back(b);
            if (++payloadBytesRead_ == payloadLen_)
                state_ = State::Byte0;
            break;
        }
    }
};

} // namespace ntm::ws
