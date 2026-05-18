// SPDX-License-Identifier: MIT
//
// IPRangeResolver + IPDataUpdater
// --------------------------------
// Replaces the previous libmaxminddb-backed GeoIPResolver and EntityResolver.
//
// Data source: https://iptoasn.com/data/ip2asn-combined.tsv.gz
//   Format: range_start \t range_end \t AS_number \t country_code \t AS_description
//   Both IPv4 and IPv6 ranges appear in the same file.
//   Data is released under CC0 (public domain).
//
// Design:
//   - Load the gzipped TSV via zlib (gzopen/gzgets).
//   - Store two sorted vectors (IPv4 and IPv6 separately) and binary-search by
//     start address. Each entry contains the inclusive end, the ASN, the 2-char
//     country code, and the AS description string.
//   - Hot reload by atomically swapping a shared_ptr held by IPDataUpdater. Each
//     lookup grabs a snapshot pointer once and uses it for the duration.
//
// Auto-update:
//   - IPDataUpdater owns a background thread that wakes every check_interval
//     (default 1 hour) and, if the local file is older than refresh_days
//     (default 7), downloads a fresh copy via libcurl over HTTPS.
//   - Downloads go to "<path>.tmp" and are renamed only after a successful
//     parse. A failed download/parse leaves the previous file (and resolver)
//     intact.
//   - On startup the updater attempts an immediate load of the existing file
//     (if any) and schedules an async refresh if the file is missing or stale.

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <curl/curl.h>
#include <zlib.h>

namespace ntm {

class IPRangeResolver
{
public:
    static constexpr const char *kUnknownCountry = "??";
    static constexpr const char *kUnknownEntity  = "AS??";

    struct V4Range
    {
        std::uint32_t start{0};
        std::uint32_t end{0};
        std::uint32_t asn{0};
        std::array<char, 2> country{{'?', '?'}};
        std::string as_desc;
    };

    struct V6Range
    {
        std::array<std::uint8_t, 16> start{};
        std::array<std::uint8_t, 16> end{};
        std::uint32_t asn{0};
        std::array<char, 2> country{{'?', '?'}};
        std::string as_desc;
    };

    // Load from a TSV file (optionally gzipped — detected by the file extension
    // OR by attempting gzopen; we use gzopen for everything which handles both
    // plain text and gzip thanks to its transparent fallback).
    // Returns nullptr on failure; the caller may log via its own facility.
    static std::shared_ptr<IPRangeResolver> loadFromFile(const std::string &path,
                                                         std::string *errorOut = nullptr)
    {
        auto out = std::shared_ptr<IPRangeResolver>(new IPRangeResolver);
        if (!out->loadImpl(path, errorOut))
            return nullptr;
        out->finalize();
        return out;
    }

    std::size_t v4Ranges() const { return v4_.size(); }
    std::size_t v6Ranges() const { return v6_.size(); }
    std::int64_t mtimeEpochSec() const { return mtime_epoch_sec_; }

    // Returns the 2-char ISO country code or "??".
    std::string countryFor(const std::string &ip) const
    {
        IpKey k;
        if (!parseIp(ip, k))
            return kUnknownCountry;
        if (k.is_v4)
        {
            const V4Range *r = lookupV4(k.v4);
            if (!r || r->country[0] == '?') return kUnknownCountry;
            return std::string(r->country.data(), 2);
        }
        const V6Range *r = lookupV6(k.v6);
        if (!r || r->country[0] == '?') return kUnknownCountry;
        return std::string(r->country.data(), 2);
    }

    // Returns "AS<num> <desc>" or "AS<num>" or "AS??".
    std::string entityFor(const std::string &ip) const
    {
        IpKey k;
        if (!parseIp(ip, k))
            return kUnknownEntity;
        std::uint32_t asn = 0;
        const std::string *desc = nullptr;
        if (k.is_v4)
        {
            const V4Range *r = lookupV4(k.v4);
            if (!r || r->asn == 0) return kUnknownEntity;
            asn = r->asn;
            desc = &r->as_desc;
        }
        else
        {
            const V6Range *r = lookupV6(k.v6);
            if (!r || r->asn == 0) return kUnknownEntity;
            asn = r->asn;
            desc = &r->as_desc;
        }
        std::string out = "AS" + std::to_string(asn);
        if (desc && !desc->empty())
        {
            out.push_back(' ');
            out.append(*desc);
        }
        return out;
    }

private:
    IPRangeResolver() = default;

    struct IpKey
    {
        bool is_v4{true};
        std::uint32_t v4{0};
        std::array<std::uint8_t, 16> v6{};
    };

    static bool parseIp(const std::string &ip, IpKey &out)
    {
        if (ip.empty()) return false;
        struct in_addr a4;
        if (::inet_pton(AF_INET, ip.c_str(), &a4) == 1)
        {
            out.is_v4 = true;
            out.v4 = ntohl(a4.s_addr);
            return true;
        }
        struct in6_addr a6;
        if (::inet_pton(AF_INET6, ip.c_str(), &a6) == 1)
        {
            out.is_v4 = false;
            std::memcpy(out.v6.data(), &a6, 16);
            return true;
        }
        return false;
    }

    const V4Range *lookupV4(std::uint32_t ip) const
    {
        auto it = std::upper_bound(v4_.begin(), v4_.end(), ip,
            [](std::uint32_t v, const V4Range &r) { return v < r.start; });
        if (it == v4_.begin()) return nullptr;
        --it;
        return (ip >= it->start && ip <= it->end) ? &*it : nullptr;
    }

    const V6Range *lookupV6(const std::array<std::uint8_t, 16> &ip) const
    {
        auto it = std::upper_bound(v6_.begin(), v6_.end(), ip,
            [](const std::array<std::uint8_t, 16> &v, const V6Range &r) {
                return v < r.start;
            });
        if (it == v6_.begin()) return nullptr;
        --it;
        return (ip >= it->start && ip <= it->end) ? &*it : nullptr;
    }

    bool loadImpl(const std::string &path, std::string *errorOut)
    {
        gzFile gz = ::gzopen(path.c_str(), "rb");
        if (!gz)
        {
            if (errorOut) *errorOut = "gzopen failed for " + path;
            return false;
        }

        struct GzCloser
        {
            gzFile g;
            ~GzCloser() { if (g) ::gzclose(g); }
        } guard{gz};

        // We need lines up to a few KB (AS description strings are usually
        // small but we leave headroom). gzgets reads up to len-1 bytes.
        constexpr std::size_t kLineMax = 8192;
        std::vector<char> linebuf(kLineMax);
        std::size_t lineNo = 0;
        v4_.reserve(800000);
        v6_.reserve(150000);

        while (::gzgets(gz, linebuf.data(), static_cast<int>(linebuf.size())))
        {
            ++lineNo;
            std::string_view line(linebuf.data());
            // Trim trailing \r\n.
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.remove_suffix(1);
            if (line.empty() || line[0] == '#')
                continue;

            // Split by tab: start \t end \t asn \t country \t desc(remaining)
            std::size_t f1 = line.find('\t');
            if (f1 == std::string_view::npos) continue;
            std::size_t f2 = line.find('\t', f1 + 1);
            if (f2 == std::string_view::npos) continue;
            std::size_t f3 = line.find('\t', f2 + 1);
            if (f3 == std::string_view::npos) continue;
            std::size_t f4 = line.find('\t', f3 + 1);
            if (f4 == std::string_view::npos) continue;

            std::string startStr(line.substr(0, f1));
            std::string endStr(line.substr(f1 + 1, f2 - f1 - 1));
            std::string asnStr(line.substr(f2 + 1, f3 - f2 - 1));
            std::string cc(line.substr(f3 + 1, f4 - f3 - 1));
            std::string_view desc = line.substr(f4 + 1);

            std::uint32_t asn = 0;
            try { asn = static_cast<std::uint32_t>(std::stoul(asnStr)); }
            catch (...) { continue; }

            std::array<char, 2> ccArr{{'?', '?'}};
            if (cc.size() == 2 && cc != "None")
            {
                ccArr[0] = cc[0];
                ccArr[1] = cc[1];
            }

            // Detect IPv4 vs IPv6 by attempting inet_pton on the start.
            struct in_addr a4;
            struct in6_addr a6;
            if (::inet_pton(AF_INET, startStr.c_str(), &a4) == 1)
            {
                struct in_addr b4;
                if (::inet_pton(AF_INET, endStr.c_str(), &b4) != 1)
                    continue;
                V4Range r;
                r.start = ntohl(a4.s_addr);
                r.end = ntohl(b4.s_addr);
                r.asn = asn;
                r.country = ccArr;
                r.as_desc.assign(desc.data(), desc.size());
                v4_.push_back(std::move(r));
            }
            else if (::inet_pton(AF_INET6, startStr.c_str(), &a6) == 1)
            {
                struct in6_addr b6;
                if (::inet_pton(AF_INET6, endStr.c_str(), &b6) != 1)
                    continue;
                V6Range r;
                std::memcpy(r.start.data(), &a6, 16);
                std::memcpy(r.end.data(), &b6, 16);
                r.asn = asn;
                r.country = ccArr;
                r.as_desc.assign(desc.data(), desc.size());
                v6_.push_back(std::move(r));
            }
            else
            {
                continue;
            }
        }

        if (v4_.empty() && v6_.empty())
        {
            if (errorOut) *errorOut = "no valid ranges parsed from " + path;
            return false;
        }

        // Record source mtime for staleness checks by the updater.
        struct stat st;
        if (::stat(path.c_str(), &st) == 0)
            mtime_epoch_sec_ = static_cast<std::int64_t>(st.st_mtime);

        return true;
    }

    void finalize()
    {
        std::sort(v4_.begin(), v4_.end(),
                  [](const V4Range &a, const V4Range &b) { return a.start < b.start; });
        std::sort(v6_.begin(), v6_.end(),
                  [](const V6Range &a, const V6Range &b) { return a.start < b.start; });
        v4_.shrink_to_fit();
        v6_.shrink_to_fit();
    }

    std::vector<V4Range> v4_;
    std::vector<V6Range> v6_;
    std::int64_t mtime_epoch_sec_{0};
};

// ============================================================================
// IPDataUpdater
// ============================================================================
class IPDataUpdater
{
public:
    using Logger = std::function<void(int /*priority: 3=err 4=warn 6=info*/,
                                      const std::string & /*msg*/)>;

    struct Config
    {
        std::string path;               // Local cache path, e.g. /var/lib/ntm-server/ip2asn-combined.tsv.gz
        std::string url;                // HTTPS URL to fetch when stale.
        unsigned refresh_days{7};       // Re-download if file is older than this.
        unsigned check_interval_sec{3600}; // How often to wake and check (default 1h).
        bool auto_update{true};
        long connect_timeout_sec{30};
        long total_timeout_sec{180};
        std::int64_t max_download_bytes{200 * 1024 * 1024}; // 200 MiB sanity cap
    };

    IPDataUpdater(Config cfg, Logger logger)
        : cfg_(std::move(cfg)), log_(std::move(logger))
    {
        // libcurl global init must happen exactly once per process. We use the
        // shared global initialiser so callers can construct multiple updaters
        // safely; the curl_global_cleanup call in stop() is a no-op for the
        // second instance.
        static std::once_flag globalInit;
        std::call_once(globalInit, []() {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            // Pair the once-only init with a once-only cleanup at normal
            // process exit. atexit handlers run after main() returns (workers
            // already joined), so no curl_easy_* call can still be in flight.
            std::atexit([] { curl_global_cleanup(); });
        });
    }

    ~IPDataUpdater() { stop(); }

    // Attempt to load the existing local file synchronously. Returns true if
    // the file existed and parsed; false otherwise. Always safe to call.
    bool loadInitial()
    {
        std::string err;
        auto r = IPRangeResolver::loadFromFile(cfg_.path, &err);
        if (r)
        {
            log(6, "IPDataUpdater: loaded " + cfg_.path + " ("
                   + std::to_string(r->v4Ranges()) + " v4 ranges, "
                   + std::to_string(r->v6Ranges()) + " v6 ranges)");
            store(r);
            return true;
        }
        log(4, "IPDataUpdater: cannot load existing local data: " + err);
        return false;
    }

    void start()
    {
        running_.store(true);
        thread_ = std::thread(&IPDataUpdater::run, this);
    }

    void stop()
    {
        if (!running_.exchange(false)) return;
        {
            std::lock_guard<std::mutex> lk(cv_mtx_);
            cv_.notify_all();
        }
        if (thread_.joinable()) thread_.join();
    }

    // Returns the current resolver snapshot or nullptr if none loaded yet.
    std::shared_ptr<const IPRangeResolver> get() const
    {
        std::lock_guard<std::mutex> lk(mtx_);
        return current_;
    }

private:
    void run()
    {
        try
        {
            // Initial decision: if file missing or older than refresh_days,
            // try to download right away. Otherwise just sleep until the next
            // check tick.
            if (cfg_.auto_update)
            {
                if (needsRefresh())
                    refreshOnce();
            }

            while (running_.load())
            {
                std::unique_lock<std::mutex> lk(cv_mtx_);
                cv_.wait_for(lk, std::chrono::seconds(cfg_.check_interval_sec),
                             [this] { return !running_.load(); });
                if (!running_.load()) break;
                if (cfg_.auto_update && needsRefresh())
                    refreshOnce();
            }
        }
        catch (const std::exception &e)
        {
            log(3, std::string("IPDataUpdater thread exception: ") + e.what());
        }
        catch (...)
        {
            log(3, "IPDataUpdater thread caught unknown exception");
        }
    }

    bool needsRefresh() const
    {
        struct stat st;
        if (::stat(cfg_.path.c_str(), &st) != 0)
            return true;  // file missing
        std::time_t now = std::time(nullptr);
        const std::int64_t ageSec = static_cast<std::int64_t>(now) -
                                    static_cast<std::int64_t>(st.st_mtime);
        const std::int64_t limit = static_cast<std::int64_t>(cfg_.refresh_days) * 86400;
        return ageSec >= limit;
    }

    void refreshOnce()
    {
        log(6, "IPDataUpdater: refreshing " + cfg_.path + " from " + cfg_.url);

        const std::string tmpPath = cfg_.path + ".tmp";
        // Make sure the destination directory exists. mkdir errors that aren't
        // EEXIST will surface via the fopen attempt below.
        ensureDirExists(cfg_.path);

        // Remove any leftover tmp from a previous crashed run.
        ::unlink(tmpPath.c_str());

        if (!downloadTo(tmpPath))
        {
            log(3, "IPDataUpdater: download failed; keeping existing data");
            ::unlink(tmpPath.c_str());
            return;
        }

        // Parse the freshly downloaded file before swapping.
        std::string err;
        auto fresh = IPRangeResolver::loadFromFile(tmpPath, &err);
        if (!fresh)
        {
            log(3, "IPDataUpdater: downloaded file failed to parse (" + err
                   + "); keeping existing data");
            ::unlink(tmpPath.c_str());
            return;
        }

        // Atomic rename into final location.
        if (::rename(tmpPath.c_str(), cfg_.path.c_str()) != 0)
        {
            log(3, std::string("IPDataUpdater: rename(") + tmpPath + " -> "
                   + cfg_.path + ") failed: " + std::strerror(errno));
            // We still install the parsed resolver in memory so lookups work.
        }

        store(fresh);
        log(6, "IPDataUpdater: installed new resolver ("
               + std::to_string(fresh->v4Ranges()) + " v4 ranges, "
               + std::to_string(fresh->v6Ranges()) + " v6 ranges)");
    }

    void store(std::shared_ptr<const IPRangeResolver> r)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        current_ = std::move(r);
    }

    static std::size_t curlWriteCb(char *ptr, std::size_t size, std::size_t nmemb,
                                   void *userdata)
    {
        auto *ctx = static_cast<WriteCtx *>(userdata);
        const std::size_t bytes = size * nmemb;
        if (ctx->maxBytes > 0 && ctx->written + bytes > ctx->maxBytes)
            return 0;  // exceeds cap; curl will fail the transfer
        std::size_t w = std::fwrite(ptr, 1, bytes, ctx->fp);
        if (w != bytes) return 0;
        ctx->written += bytes;
        return bytes;
    }

    struct WriteCtx
    {
        std::FILE *fp{nullptr};
        std::size_t written{0};
        std::size_t maxBytes{0};
    };

    bool downloadTo(const std::string &tmpPath)
    {
        std::FILE *fp = std::fopen(tmpPath.c_str(), "wb");
        if (!fp)
        {
            log(3, std::string("IPDataUpdater: cannot open ") + tmpPath
                   + " for writing: " + std::strerror(errno));
            return false;
        }
        struct FpCloser
        {
            std::FILE *f;
            ~FpCloser() { if (f) std::fclose(f); }
        } closer{fp};

        CURL *curl = curl_easy_init();
        if (!curl)
        {
            log(3, "IPDataUpdater: curl_easy_init failed");
            return false;
        }
        struct CurlCleaner
        {
            CURL *c;
            ~CurlCleaner() { if (c) curl_easy_cleanup(c); }
        } cleaner{curl};

        WriteCtx ctx;
        ctx.fp = fp;
        ctx.maxBytes = static_cast<std::size_t>(cfg_.max_download_bytes);

        curl_easy_setopt(curl, CURLOPT_URL, cfg_.url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cfg_.connect_timeout_sec);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg_.total_timeout_sec);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // safe for multi-threaded
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ntm-server/1.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        CURLcode rc = curl_easy_perform(curl);
        if (rc != CURLE_OK)
        {
            log(3, std::string("IPDataUpdater: curl transfer failed: ")
                   + curl_easy_strerror(rc));
            return false;
        }

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 0 && (http_code < 200 || http_code >= 300))
        {
            log(3, "IPDataUpdater: HTTP status " + std::to_string(http_code));
            return false;
        }
        std::fflush(fp);
        return true;
    }

    static void ensureDirExists(const std::string &filePath)
    {
        auto pos = filePath.find_last_of('/');
        if (pos == std::string::npos || pos == 0) return;
        std::string dir = filePath.substr(0, pos);
        // mkdir -p semantics with a tiny loop.
        std::string acc;
        std::size_t start = 0;
        if (!dir.empty() && dir[0] == '/') { acc = "/"; start = 1; }
        while (start <= dir.size())
        {
            auto next = dir.find('/', start);
            std::string part = dir.substr(start, (next == std::string::npos)
                                                 ? std::string::npos
                                                 : next - start);
            if (!part.empty())
            {
                if (!acc.empty() && acc.back() != '/') acc.push_back('/');
                acc += part;
                ::mkdir(acc.c_str(), 0755);  // ignore EEXIST etc.
            }
            if (next == std::string::npos) break;
            start = next + 1;
        }
    }

    void log(int prio, const std::string &msg) const
    {
        if (log_) log_(prio, msg);
    }

    Config cfg_;
    Logger log_;

    mutable std::mutex mtx_;
    std::shared_ptr<const IPRangeResolver> current_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    mutable std::mutex cv_mtx_;
    std::condition_variable cv_;
};

} // namespace ntm
