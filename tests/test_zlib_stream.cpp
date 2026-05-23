// test_zlib_stream.cpp
// Unit tests for ZlibDeflater and ZlibInflater (src/zlib_stream.hpp).
// Covers: empty input, single-call round-trip, multi-call streaming,
//         realistic D-line payloads, chunk-size independence.

#include "ntm_test.hpp"
#include "../src/zlib_stream.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace ntm;

// Helper: deflate `data`, then inflate result and return as string.
static std::string roundTrip(const std::string &data)
{
    ZlibDeflater deflater;
    std::vector<std::uint8_t> compressed;
    if (!deflater.feed(data.data(), data.size(), compressed))
        return "<deflate-error>";

    ZlibInflater inflater;
    std::vector<std::uint8_t> decompressed;
    if (!inflater.feed(compressed.data(), compressed.size(), decompressed))
        return "<inflate-error>";

    return std::string(reinterpret_cast<const char *>(decompressed.data()),
                       decompressed.size());
}

// ═══════════════════════════════════════════════════════════════════════════
// Basic round-trip
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: empty input round-trips to empty output")
{
    std::string result = roundTrip("");
    REQUIRE_EQ(result, std::string{});
}

TEST_CASE("zlib: single D-line round-trips correctly")
{
    std::string line = "D eth0 10.0.0.1 8.8.8.8 1500\n";
    REQUIRE_EQ(roundTrip(line), line);
}

TEST_CASE("zlib: H-line round-trips correctly")
{
    std::string line =
        "H pcap_recv=1000000 pcap_drop=0 buf_drop=0 ver=1.11.0 "
        "wire_proto=2 platform=linux-amd64 agg_interval_ms=1200 agg_flows=47\n";
    REQUIRE_EQ(roundTrip(line), line);
}

TEST_CASE("zlib: X-line round-trips correctly")
{
    std::string line = "X 203.0.113.1\n";
    REQUIRE_EQ(roundTrip(line), line);
}

TEST_CASE("zlib: A-line round-trips correctly")
{
    std::string line = "A 192.168.1.100\n";
    REQUIRE_EQ(roundTrip(line), line);
}

TEST_CASE("zlib: 1000 D-lines round-trip correctly")
{
    std::string payload;
    payload.reserve(50 * 1000);
    for (int i = 0; i < 1000; ++i)
    {
        payload += "D eth0 10.0.0.";
        payload += std::to_string(i % 256);
        payload += " 93.184.216.34 ";
        payload += std::to_string(1400 + (i % 100));
        payload += '\n';
    }
    REQUIRE_EQ(roundTrip(payload), payload);
}

// ═══════════════════════════════════════════════════════════════════════════
// Compression actually reduces size (repetitive data compresses well)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: 1000 identical D-lines compress to less than half input size")
{
    std::string line = "D eth0 192.168.1.1 93.184.216.34 1500\n";
    std::string payload;
    for (int i = 0; i < 1000; ++i) payload += line;

    ZlibDeflater deflater;
    std::vector<std::uint8_t> compressed;
    REQUIRE(deflater.feed(payload.data(), payload.size(), compressed));
    // Identical lines compress extremely well; expect >4x ratio.
    REQUIRE(compressed.size() < payload.size() / 4);
}

// ═══════════════════════════════════════════════════════════════════════════
// Streaming: deflate in multiple calls, inflate all at once
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: multiple deflate calls, single inflate call")
{
    ZlibDeflater deflater;
    std::vector<std::uint8_t> compressed;

    std::string part1 = "D eth0 10.0.0.1 8.8.8.8 1400\n";
    std::string part2 = "D eth0 10.0.0.2 1.1.1.1 800\n";
    std::string part3 = "H pcap_recv=500 pcap_drop=0 buf_drop=0 ver=1.11.0 wire_proto=2\n";

    REQUIRE(deflater.feed(part1.data(), part1.size(), compressed));
    REQUIRE(deflater.feed(part2.data(), part2.size(), compressed));
    REQUIRE(deflater.feed(part3.data(), part3.size(), compressed));

    ZlibInflater inflater;
    std::vector<std::uint8_t> decompressed;
    REQUIRE(inflater.feed(compressed.data(), compressed.size(), decompressed));

    std::string result(reinterpret_cast<const char *>(decompressed.data()),
                       decompressed.size());
    REQUIRE_EQ(result, part1 + part2 + part3);
}

// ═══════════════════════════════════════════════════════════════════════════
// Streaming: single deflate call, inflate in byte-by-byte chunks
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: single deflate, inflate byte-by-byte")
{
    std::string payload = "D eth0 10.0.0.1 8.8.8.8 1500\n"
                          "D eth0 10.0.0.1 1.1.1.1 600\n";

    ZlibDeflater deflater;
    std::vector<std::uint8_t> compressed;
    REQUIRE(deflater.feed(payload.data(), payload.size(), compressed));

    ZlibInflater inflater;
    std::vector<std::uint8_t> decompressed;
    for (std::uint8_t byte : compressed)
        REQUIRE(inflater.feed(&byte, 1, decompressed));

    std::string result(reinterpret_cast<const char *>(decompressed.data()),
                       decompressed.size());
    REQUIRE_EQ(result, payload);
}

// ═══════════════════════════════════════════════════════════════════════════
// Streaming: interleaved deflate + inflate (simulates client→server pipe)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: interleaved per-flush round-trip simulates live pipe")
{
    // Simulate client sending 10 flush cycles; each cycle has 5 D-lines.
    ZlibDeflater deflater;
    ZlibInflater inflater;

    std::string allInput;
    std::string allOutput;

    for (int flush = 0; flush < 10; ++flush)
    {
        std::string chunk;
        for (int d = 0; d < 5; ++d)
        {
            chunk += "D eth0 10.0.0." + std::to_string(flush * 5 + d)
                   + " 93.184.216.34 1500\n";
        }
        allInput += chunk;

        // Client compresses and "sends"
        std::vector<std::uint8_t> compressed;
        REQUIRE(deflater.feed(chunk.data(), chunk.size(), compressed));

        // Server receives and inflates
        std::vector<std::uint8_t> decompressed;
        REQUIRE(inflater.feed(compressed.data(), compressed.size(), decompressed));
        allOutput.append(reinterpret_cast<const char *>(decompressed.data()),
                         decompressed.size());
    }

    REQUIRE_EQ(allOutput, allInput);
}

// ═══════════════════════════════════════════════════════════════════════════
// Feed methods return true on valid input, false on corruption
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("zlib: inflater returns false on corrupt data")
{
    ZlibInflater inflater;
    // Random non-zlib bytes — inflate should fail (Z_DATA_ERROR or Z_STREAM_ERROR).
    const std::uint8_t garbage[] = {0xFF, 0xFE, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    std::vector<std::uint8_t> out;
    bool ok = inflater.feed(garbage, sizeof(garbage), out);
    REQUIRE(!ok);
}

TEST_CASE("zlib: deflater feed with zero-length data returns true (no-op)")
{
    ZlibDeflater deflater;
    std::vector<std::uint8_t> out;
    REQUIRE(deflater.feed(nullptr, 0, out));
    REQUIRE_EQ(out.size(), std::size_t{0});
}

TEST_CASE("zlib: inflater feed with zero-length data returns true (no-op)")
{
    ZlibInflater inflater;
    std::vector<std::uint8_t> out;
    REQUIRE(inflater.feed(nullptr, 0, out));
    REQUIRE_EQ(out.size(), std::size_t{0});
}
