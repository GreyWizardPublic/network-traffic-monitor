#pragma once
// zlib_stream.hpp — streaming zlib deflate/inflate wrappers for the NTM data phase.
//
// The data phase is a long-lived stream of newline-terminated UTF-8 lines.  IP
// addresses and line prefixes repeat heavily, giving zlib deflate compression
// ratios of 3-8× in practice.
//
// Design contract:
//   • ZlibDeflater::feed()  always uses Z_SYNC_FLUSH so the output is decompressible
//     immediately without waiting for the next flush boundary.
//   • ZlibInflater::feed()  accumulates output into the caller-supplied vector;
//     the caller is responsible for draining that vector into its line buffer.
//   • Both classes are NOT thread-safe; the caller must ensure single-threaded use.
//   • Both classes are Linux-only (the Windows client links no zlib).

#include <zlib.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ntm
{

// ---------------------------------------------------------------------------
// ZlibDeflater
// ---------------------------------------------------------------------------
class ZlibDeflater
{
public:
    ZlibDeflater()
    {
        zs_.zalloc = Z_NULL;
        zs_.zfree  = Z_NULL;
        zs_.opaque = Z_NULL;
        // Z_DEFAULT_COMPRESSION balances CPU vs ratio; level 6 in practice.
        deflateInit(&zs_, Z_DEFAULT_COMPRESSION);
    }

    ~ZlibDeflater() { deflateEnd(&zs_); }

    // Not copyable / not movable (z_stream contains internal pointers).
    ZlibDeflater(const ZlibDeflater &)            = delete;
    ZlibDeflater &operator=(const ZlibDeflater &) = delete;

    // Compress `len` bytes at `input` and **append** compressed bytes to `out`.
    // Uses Z_SYNC_FLUSH — all bytes are flushed to a deflate sync point so the
    // remote ZlibInflater can decompress immediately after this call returns.
    // Returns false on a fatal zlib error (should never happen in normal use).
    bool feed(const void *input, std::size_t len, std::vector<std::uint8_t> &out)
    {
        if (len == 0) return true;
        zs_.next_in  = const_cast<Bytef *>(static_cast<const Bytef *>(input));
        zs_.avail_in = static_cast<uInt>(len);

        std::uint8_t buf[8192];
        do {
            zs_.next_out  = buf;
            zs_.avail_out = static_cast<uInt>(sizeof(buf));
            int ret = ::deflate(&zs_, Z_SYNC_FLUSH);
            if (ret != Z_OK && ret != Z_BUF_ERROR && ret != Z_STREAM_END)
                return false;  // fatal error
            std::size_t produced = sizeof(buf) - zs_.avail_out;
            if (produced > 0)
                out.insert(out.end(), buf, buf + produced);
        } while (zs_.avail_in > 0 || zs_.avail_out == 0);
        return true;
    }

private:
    z_stream zs_{};
};

// ---------------------------------------------------------------------------
// ZlibInflater
// ---------------------------------------------------------------------------
class ZlibInflater
{
public:
    ZlibInflater()
    {
        zs_.zalloc = Z_NULL;
        zs_.zfree  = Z_NULL;
        zs_.opaque = Z_NULL;
        inflateInit(&zs_);
    }

    ~ZlibInflater() { inflateEnd(&zs_); }

    ZlibInflater(const ZlibInflater &)            = delete;
    ZlibInflater &operator=(const ZlibInflater &) = delete;

    // Inflate `len` bytes at `input` and **append** decompressed bytes to `out`.
    // Returns false on zlib data corruption or format error.
    bool feed(const void *input, std::size_t len, std::vector<std::uint8_t> &out)
    {
        if (len == 0) return true;
        zs_.next_in  = const_cast<Bytef *>(static_cast<const Bytef *>(input));
        zs_.avail_in = static_cast<uInt>(len);

        std::uint8_t buf[8192];
        do {
            zs_.next_out  = buf;
            zs_.avail_out = static_cast<uInt>(sizeof(buf));
            int ret = ::inflate(&zs_, Z_NO_FLUSH);
            if (ret == Z_STREAM_END) {
                // Unexpected end-of-stream (peer closed the deflate stream).
                // Recover by resetting; the connection will likely close anyway.
                std::size_t produced = sizeof(buf) - zs_.avail_out;
                if (produced > 0) out.insert(out.end(), buf, buf + produced);
                inflateReset(&zs_);
                return true;
            }
            if (ret != Z_OK && ret != Z_BUF_ERROR)
                return false;  // data corruption or format error
            std::size_t produced = sizeof(buf) - zs_.avail_out;
            if (produced > 0)
                out.insert(out.end(), buf, buf + produced);
        } while (zs_.avail_out == 0); // output buffer full → more output may remain
        return true;
    }

private:
    z_stream zs_{};
};

} // namespace ntm
