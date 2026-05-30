#include "client.hpp"
#include "client_core.hpp"
#include "client_filelog.hpp"
#include "client_platform.hpp"
#include "client_transport.hpp"
#include "client_transport_tcptls.hpp"
#include "client_transport_websocket.hpp"
#include "flow_aggregator.hpp"
#include "proto_client_server.hpp"
#include "client_version.hpp"
#include "updater.hpp"

#include "zlib_stream.hpp"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pcap/pcap.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ntm
{

// ---------------------------------------------------------------------------
// ClientConnection
// ---------------------------------------------------------------------------

class ClientConnection
{
public:
    ClientConnection(std::string host, std::uint16_t port,
                     std::string identityPath = {},
                     std::string tlsCaPath = {},
                     std::string tlsServerCertPath = {},
                     std::size_t sendBufferBytes = 0,
                     std::string externalIpUrl = "http://checkip.amazonaws.com/",
                     unsigned externalIpTimeoutMs = 5000,
                     std::atomic<bool> *gRunning = nullptr,
                     unsigned reconnectMaxAttempts = 10,
                     unsigned reconnectIntervalSec = 60,
                     AdaptiveInterval::Config aggCfg = AdaptiveInterval::Config{},
                     std::uint32_t aggMaxFlows = kAggMaxFlows,
                     bool useCompression = true,
                     bool isDaemon = false,
                     bool verbose = false,
                     TransportMode transportMode = TransportMode::TcpTls,
                     bool autoUpdate = false)
        : aggInterval_(aggCfg)
        , aggMaxFlows_(aggMaxFlows)
        , useCompression_(useCompression)
        , cfgSendBufferBytes_(sendBufferBytes)
        , cfgAutoUpdate_(autoUpdate)
        , cfgAggTargetLinesPerSec_(aggCfg.targetLinesPerSec)
        , cfgAggMinIntervalMs_(aggCfg.minIntervalMs)
        , cfgAggMaxIntervalMs_(aggCfg.maxIntervalMs)
        , host_(std::move(host)), port_(port)
        , identityPath_(std::move(identityPath))
        , tlsCaPath_(std::move(tlsCaPath))
        , tlsServerCertPath_(std::move(tlsServerCertPath))
        , externalIpUrl_(std::move(externalIpUrl))
        , externalIpTimeoutMs_(externalIpTimeoutMs)
        , reconnectMaxAttempts_(reconnectMaxAttempts)
        , reconnectIntervalSec_(reconnectIntervalSec)
        , g_runningPtr_(gRunning)
        , isDaemon_(isDaemon)
        , verbose_(verbose)
        , transportMode_(transportMode)
    {
        // flushBuffer_ is written by the aggregation flush path; reserve a reasonable
        // initial capacity to avoid frequent reallocations.
        flushBuffer_.reserve(kSendBufferDefaultBytes);

        if (!tlsCaPath_.empty() || !tlsServerCertPath_.empty())
        {
            sslCtx_ = createClientTLSContext(tlsCaPath_, tlsServerCertPath_);
            if (!sslCtx_)
            {
                std::cerr << "ntm-client: failed to create TLS context\n";
                ERR_print_errors_fp(stderr);
            }
        }
        runningSender_.store(true);
        senderThread_ = std::thread(&ClientConnection::senderLoop, this);
        netMonitor_.start();
    }

    ~ClientConnection()
    {
        close();
        if (sslCtx_) { SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; }
    }

    void setCfg(ClientConfig c) { cfg_ = std::move(c); }

    bool connectOnce()
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        lastError_.clear();
        return connectUnlocked();
    }

    std::string lastError() const
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        return lastError_;
    }

    void close()
    {
        netMonitor_.stop();
        runningSender_.store(false);
        queueCv_.notify_all();
        if (senderThread_.joinable()) senderThread_.join();
        std::lock_guard<std::mutex> lock(connectionMutex_);
        closeUnlocked();
    }

    // Hot path: accumulate bytes into the flow table.  One mutex lock per packet.
    void accumulateFlow(const PacketMeta &meta)
    {
        AggFlowKey key{meta.iface, meta.srcIp, meta.dstIp};
        std::size_t sz;
        {
            std::lock_guard<std::mutex> lock(flowMutex_);
            flowTable_[std::move(key)] += meta.bytes;
            sz = flowTable_.size();
        }
        if (sz >= aggMaxFlows_)
            queueCv_.notify_one();   // force an early flush (cap hit)
    }

    void addPcapStats(std::uint32_t recv, std::uint32_t drop)
    {
        totalPcapRecv_.fetch_add(recv, std::memory_order_relaxed);
        totalPcapDrop_.fetch_add(drop, std::memory_order_relaxed);
    }

private:
    std::mutex               queueMutex_;
    std::vector<char>        sendBuffer_;   // sniffers write here (under queueMutex_)
    std::vector<char>        flushBuffer_;  // sender reads from here (no lock needed)
    std::size_t              contentEnd_{0};
    std::condition_variable  queueCv_;
    std::atomic<bool>        runningSender_{false};
    std::thread              senderThread_;

    // ── Flow aggregation ────────────────────────────────────────────────────
    // Sniffer threads write here (under flowMutex_); sender drains it.
    std::mutex               flowMutex_;
    FlowMap                  flowTable_;
    FlowMap                  flowLocalTable_;  // swapped in on flush (no alloc per flush)
    AdaptiveInterval         aggInterval_;
    std::uint32_t            aggMaxFlows_{kAggMaxFlows};
    std::uint32_t            aggLastFlows_{0}; // flows emitted in last flush — reported in H-line

    // ── Config snapshot (emitted in every H-line for admin visibility) ─────────
    std::size_t              cfgSendBufferBytes_{0};
    bool                     cfgAutoUpdate_{false};
    std::uint32_t            cfgAggTargetLinesPerSec_{500};
    std::uint32_t            cfgAggMinIntervalMs_{100};
    std::uint32_t            cfgAggMaxIntervalMs_{5000};

    // ── zlib compression ─────────────────────────────────────────────────────
    bool                     useCompression_{true};  // from config; actual use depends on negotiation
    std::unique_ptr<ZlibDeflater> deflater_;   // non-null when compression is active on this session
    std::vector<std::uint8_t>     compBuf_;    // reused scratch buffer for compressed output

    // ── Connection ──────────────────────────────────────────────────────────
    mutable std::mutex       connectionMutex_;
    std::string              host_;
    std::uint16_t            port_;
    SSL_CTX                 *sslCtx_{nullptr};
    std::unique_ptr<ITransport> transport_;      // active connection; null when disconnected
    TransportMode            transportMode_{TransportMode::TcpTls};
    std::chrono::steady_clock::time_point sessionStart_;
    std::string              identityPath_;
    std::string              tlsCaPath_;
    std::string              tlsServerCertPath_;
    std::string              externalIpUrl_;
    unsigned                 externalIpTimeoutMs_{5000};
    std::int64_t             lastReannounceTime_{0};
    std::atomic<std::int64_t>  lastHealthReportSec_{0};
    std::atomic<std::uint64_t> totalPcapRecv_{0};
    std::atomic<std::uint64_t> totalPcapDrop_{0};
    std::atomic<std::uint64_t> sendBufDrops_{0};
    mutable std::string      lastError_;
    unsigned                 reconnectMaxAttempts_{10};
    unsigned                 reconnectIntervalSec_{60};
    unsigned                 reconnectFailures_{0};
    std::chrono::steady_clock::time_point lastReconnectAttempt_{};
    std::atomic<bool>       *g_runningPtr_{nullptr};
    bool                     isDaemon_{false};
    bool                     verbose_{false};

    // Wire-proto v3: accumulator for partial C-lines from the server.
    // Populated by pollCtrlLines() in the sender loop; never accessed from other threads.
    std::string              ctrlInBuf_;

    // Wire-proto v4: stored config snapshot for the server-pushed auto-update path.
    ClientConfig             cfg_;

    platform::NetworkMonitor netMonitor_;

    // Write `data` to the active transport, compressing via zlib if compression
    // is active.  Falls back to a plain write if no deflater is set
    // (v2 auth or --no-compress).  transport_ must be non-null when called.
    bool deflateAndWrite(const void *data, std::size_t len)
    {
        if (len == 0) return true;
        if (deflater_)
        {
            compBuf_.clear();
            if (!deflater_->feed(data, len, compBuf_)) return false;
            return transport_->writeExact(compBuf_.data(), compBuf_.size());
        }
        return transport_->writeExact(data, len);
    }

    // Send the initial LAN announce (X + A lines).  transport_ must be live.
    bool sendAnnounce()
    {
        auto lanAddrs = platform::collectLanAddresses();
        if (lanAddrs.empty()) return true;

        std::string extIp = platform::queryExternalIP(externalIpUrl_, externalIpTimeoutMs_);
        std::string xLine = std::string(kExtIPLinePrefix)
                          + (extIp.empty() ? kExtIPNull : extIp) + '\n';
        if (!deflateAndWrite(xLine.data(), xLine.size())) return false;

        for (const auto &ip : lanAddrs)
        {
            std::string aLine = std::string(kAddrLinePrefix) + ip + '\n';
            if (!deflateAndWrite(aLine.data(), aLine.size())) return false;
        }

        lastReannounceTime_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return true;
    }

    // Process one incoming C-line (server→client control command, wire-proto v3).
    // Called under connectionMutex_ with an active transport_.
    // Sends the corresponding L-line response(s) via deflateAndWrite.
    void processCtrlLine(const std::string &line)
    {
        // Strip the "C " prefix.
        if (line.size() < 2 || line[0] != 'C' || line[1] != ' ') return;
        const std::string body = line.substr(2);

        // ── C set_loglevel <level> ──────────────────────────────────────────
        if (body.rfind("set_loglevel ", 0) == 0)
        {
            std::string level = body.substr(13);
            platform::LogLevel lv = platform::LogLevel::Info;
            if (level == "Warn") lv = platform::LogLevel::Warn;
            else if (level == "Err") lv = platform::LogLevel::Err;
            else level = "Info";
            globalFileLogger().setLevel(lv);
            const std::string ack = std::string(kLogRespLinePrefix)
                                  + "ack set_loglevel " + level + "\n";
            deflateAndWrite(ack.data(), ack.size());
            platform::ntmLog(lv, isDaemon_,
                             "ntm-client: log level changed to " + level + " by admin");
            return;
        }

        // Extract req_id (second token for all remaining commands).
        const std::size_t sp1 = body.find(' ');
        if (sp1 == std::string::npos) return;
        const std::string cmd   = body.substr(0, sp1);
        const std::size_t sp2   = body.find(' ', sp1 + 1);
        const std::string reqId = (sp2 == std::string::npos)
            ? body.substr(sp1 + 1)
            : body.substr(sp1 + 1, sp2 - sp1 - 1);
        if (reqId.empty() || reqId.size() > kCtrlReqIdMaxLen) return;

        auto sendErr = [&](const std::string &code, const std::string &msg) {
            const std::string errLine = std::string(kLogRespLinePrefix)
                + "err " + reqId + " " + code + " " + msg + "\n";
            deflateAndWrite(errLine.data(), errLine.size());
        };

        // ── C log_list <req_id> ─────────────────────────────────────────────
        if (cmd == "log_list")
        {
            if (!globalFileLogger().active())
            {
                sendErr("unavailable", "file-logging-not-active");
                return;
            }
            const auto files = globalFileLogger().listFiles();
            {
                const std::string begin = std::string(kLogRespLinePrefix)
                    + "list " + reqId + " begin " + std::to_string(files.size()) + "\n";
                deflateAndWrite(begin.data(), begin.size());
            }
            for (const auto &f : files)
            {
                const std::string entry = std::string(kLogRespLinePrefix)
                    + "list " + reqId + " file "
                    + f.name + " "
                    + std::to_string(f.size) + " "
                    + f.mtime + "\n";
                deflateAndWrite(entry.data(), entry.size());
            }
            {
                const std::string end = std::string(kLogRespLinePrefix)
                    + "list " + reqId + " end\n";
                deflateAndWrite(end.data(), end.size());
            }
            return;
        }

        // ── C log_delete_all <req_id> ───────────────────────────────────────
        if (cmd == "log_delete_all")
        {
            if (!globalFileLogger().active())
            {
                sendErr("unavailable", "file-logging-not-active");
                return;
            }
            const int n = globalFileLogger().deleteAllFiles();
            const std::string resp = std::string(kLogRespLinePrefix)
                + "del_all " + reqId + " ok " + std::to_string(n) + "\n";
            deflateAndWrite(resp.data(), resp.size());
            return;
        }

        // Remaining commands need a filename argument.
        if (sp2 == std::string::npos) return;
        const std::string filename = body.substr(sp2 + 1);
        if (filename.empty() || filename.find('/') != std::string::npos
            || filename.find('\\') != std::string::npos
            || filename.find("..") != std::string::npos)
        {
            sendErr("bad_filename", "invalid-or-missing-filename");
            return;
        }

        // ── C log_delete <req_id> <filename> ───────────────────────────────
        if (cmd == "log_delete")
        {
            if (!globalFileLogger().active())
            {
                sendErr("unavailable", "file-logging-not-active");
                return;
            }
            if (globalFileLogger().deleteFile(filename))
            {
                const std::string resp = std::string(kLogRespLinePrefix)
                    + "del " + reqId + " ok " + filename + "\n";
                deflateAndWrite(resp.data(), resp.size());
            }
            else
            {
                const std::string resp = std::string(kLogRespLinePrefix)
                    + "del " + reqId + " err " + filename + " not-found\n";
                deflateAndWrite(resp.data(), resp.size());
            }
            return;
        }

        // ── C log_get <req_id> <filename> ──────────────────────────────────
        if (cmd == "log_get")
        {
            if (!globalFileLogger().active())
            {
                sendErr("unavailable", "file-logging-not-active");
                return;
            }
            const std::string filePath = globalFileLogger().logDir() + "/" + filename;
            FILE *fp = std::fopen(filePath.c_str(), "rb");
            if (!fp)
            {
                sendErr("not_found", "file-not-found");
                return;
            }
            // Get file size.
            std::fseek(fp, 0, SEEK_END);
            const long fileSzLong = std::ftell(fp);
            std::fseek(fp, 0, SEEK_SET);
            if (fileSzLong < 0)
            {
                std::fclose(fp);
                sendErr("io_error", "cannot-stat-file");
                return;
            }
            const std::uintmax_t fileSize = static_cast<std::uintmax_t>(fileSzLong);

            // Compute SHA-256.
            std::string sha256hex;
            {
                // Re-open for hashing so reading doesn't move the position.
                FILE *hfp = std::fopen(filePath.c_str(), "rb");
                if (hfp)
                {
                    unsigned char digest[32]{};
                    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                    if (ctx)
                    {
                        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
                        std::uint8_t hashBuf[8192];
                        std::size_t nr;
                        while ((nr = std::fread(hashBuf, 1, sizeof(hashBuf), hfp)) > 0)
                            EVP_DigestUpdate(ctx, hashBuf, nr);
                        unsigned int dlen = 0;
                        EVP_DigestFinal_ex(ctx, digest, &dlen);
                        EVP_MD_CTX_free(ctx);
                    }
                    std::fclose(hfp);
                    char hexBuf[65]{};
                    for (int i = 0; i < 32; ++i)
                        std::snprintf(hexBuf + i * 2, 3, "%02x", digest[i]);
                    sha256hex = hexBuf;
                }
            }

            // Send L get begin.
            {
                const std::string hdr = std::string(kLogRespLinePrefix)
                    + "get " + reqId + " begin "
                    + filename + " "
                    + std::to_string(fileSize) + " "
                    + sha256hex + "\n";
                deflateAndWrite(hdr.data(), hdr.size());
            }

            // Send chunks (≤ 32 KiB raw → base64-encoded).
            static constexpr std::size_t kRawChunk = 32768;
            std::vector<std::uint8_t> rawChunk(kRawChunk);
            std::size_t nr;
            while ((nr = std::fread(rawChunk.data(), 1, kRawChunk, fp)) > 0)
            {
                // Base64-encode the raw chunk.
                const int b64Len = ((static_cast<int>(nr) + 2) / 3) * 4;
                std::vector<unsigned char> b64(static_cast<std::size_t>(b64Len) + 1, 0);
                EVP_EncodeBlock(b64.data(), rawChunk.data(), static_cast<int>(nr));
                const std::string chunk = std::string(kLogRespLinePrefix)
                    + "get " + reqId + " chunk "
                    + std::string(reinterpret_cast<const char *>(b64.data()),
                                  static_cast<std::size_t>(b64Len))
                    + "\n";
                if (!deflateAndWrite(chunk.data(), chunk.size()))
                {
                    std::fclose(fp);
                    return;
                }
            }
            std::fclose(fp);

            // Send L get end.
            {
                const std::string end = std::string(kLogRespLinePrefix)
                    + "get " + reqId + " end\n";
                deflateAndWrite(end.data(), end.size());
            }
            return;
        }

        // ── C update_now <req_id> ───────────────────────────────────────────
        if (cmd == "update_now")
        {
            if (!cfg_.auto_update)
            {
                sendErr("unavailable", "auto-update-disabled");
                return;
            }

            // Ack immediately so the server sees the command was received.
            {
                const std::string ack = std::string(kLogRespLinePrefix)
                    + "upd " + reqId + " ack\n";
                deflateAndWrite(ack.data(), ack.size());
            }

            // Helper: emit one L upd line.
            auto sendUpd = [&](const std::string &tail) {
                const std::string line = std::string(kLogRespLinePrefix)
                    + "upd " + reqId + " " + tail + "\n";
                deflateAndWrite(line.data(), line.size());
            };

            UpdateCallbacks cb;
            cb.onStage = [&](std::string_view s) {
                sendUpd("stage " + std::string(s));
            };
            cb.onError = [&](std::string_view s, std::string_view m) {
                sendUpd("err " + std::string(s) + " " + std::string(m));
            };
            cb.onNoop  = [&](std::string_view r) {
                sendUpd("noop " + std::string(r));
            };
            cb.onDone  = [&](std::string_view v) {
                sendUpd("done " + std::string(v));
            };

            // Run synchronously (blocks this connection for the download duration).
            // On Linux success: execv() is called after cb.onDone(); never returns.
            // On Windows success: ExitProcess(0) is called; never returns.
            // On noop/error: returns normally; connection resumes.
            doOneCheckCycle(cfg_, UpdateTrigger::ServerPush, cb);
            return;
        }
    }

    void senderLoop()
    {
        auto lastFlushTime = std::chrono::steady_clock::now();

        while (runningSender_.load())
        {
            try
            {
                // ── Wait for the adaptive interval or an early-wake signal ──────
                bool forcedFlush = false;
                {
                    std::unique_lock<std::mutex> lock(queueMutex_);
                    const auto waitMs = std::chrono::milliseconds(aggInterval_.intervalMs());
                    forcedFlush = !queueCv_.wait_for(lock, waitMs, [this] {
                        return !runningSender_.load()
                            || flowTable_.size() >= aggMaxFlows_;
                    });
                    // forcedFlush == true  → timer expired (normal)
                    // forcedFlush == false → woken early (cap hit or shutdown)
                    if (!runningSender_.load()) break;
                    forcedFlush = (flowTable_.size() >= aggMaxFlows_);
                }

                // ── Drain the flow table ─────────────────────────────────────
                {
                    std::lock_guard<std::mutex> lk(flowMutex_);
                    std::swap(flowTable_, flowLocalTable_);
                }
                const std::uint32_t flowCount =
                    static_cast<std::uint32_t>(flowLocalTable_.size());

                // Encode D-lines from the local snapshot into flushBuffer_.
                flushBuffer_.clear();
                for (const auto &kv : flowLocalTable_)
                {
                    char buf[256];
                    int len = std::snprintf(buf, sizeof(buf), "D %.64s %.46s %.46s %llu\n",
                                            kv.first.iface.c_str(),
                                            kv.first.srcIp.c_str(),
                                            kv.first.dstIp.c_str(),
                                            static_cast<unsigned long long>(kv.second));
                    if (len > 0 && static_cast<std::size_t>(len) < sizeof(buf))
                        flushBuffer_.insert(flushBuffer_.end(), buf, buf + len);
                }
                flowLocalTable_.clear();

                // Update the adaptive interval (skip for forced/cap flushes).
                if (!forcedFlush)
                {
                    aggInterval_.update(flowCount);
                    aggLastFlows_ = flowCount;
                }
                lastFlushTime = std::chrono::steady_clock::now();

                // ── Periodic bookkeeping ────────────────────────────────────
                const bool netChanged = netMonitor_.checkAndClear();
                const auto nowEpochSec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                const bool healthDue =
                    (nowEpochSec - lastHealthReportSec_.load(std::memory_order_relaxed)) >=
                    static_cast<std::int64_t>(kHealthIntervalSec);
                if (flushBuffer_.empty() && !netChanged && !healthDue) continue;

                std::lock_guard<std::mutex> connLock(connectionMutex_);
                const bool connected = transport_ && transport_->isConnected();
                if (!connected)
                {
                    const auto now = std::chrono::steady_clock::now();
                    const bool waitInterval = reconnectFailures_ > 0 &&
                        std::chrono::duration_cast<std::chrono::seconds>(
                            now - lastReconnectAttempt_).count()
                            < static_cast<std::int64_t>(reconnectIntervalSec_);
                    if (waitInterval) continue;

                    lastReconnectAttempt_ = now;
                    if (!connectUnlocked())
                    {
                        ++reconnectFailures_;
                        std::cerr << "ntm-client: reconnect attempt " << reconnectFailures_
                                  << "/" << reconnectMaxAttempts_ << " failed: "
                                  << (lastError_.empty() ? "unknown" : lastError_) << "\n";
                        if (reconnectFailures_ >= reconnectMaxAttempts_)
                        {
                            std::cerr << "ntm-client: server unreachable after "
                                      << reconnectMaxAttempts_
                                      << " attempt(s) — shutting down\n";
                            if (g_runningPtr_) g_runningPtr_->store(false);
                            runningSender_.store(false);
                            return;
                        }
                        std::cerr << "ntm-client: next reconnect attempt in "
                                  << reconnectIntervalSec_ << "s\n";
                        continue;
                    }
                    if (reconnectFailures_ > 0)
                        std::cerr << "ntm-client: reconnected successfully after "
                                  << reconnectFailures_ << " failed attempt(s)\n";
                    reconnectFailures_ = 0;
                    aggInterval_.reset();  // fresh connection — start responsive
                }

                // Wire-proto v3: poll for incoming C-lines (server→client control cmds).
                if (transport_ && transport_->isConnected())
                {
                    std::vector<std::string> ctrlLines;
                    if (!transport_->pollCtrlLines(ctrlInBuf_, ctrlLines))
                    {
                        closeUnlocked();
                    }
                    else
                    {
                        for (const auto &cl : ctrlLines)
                            processCtrlLine(cl);
                    }
                }

                if (transport_ && transport_->isConnected() && netChanged)
                {
                    if (nowEpochSec - lastReannounceTime_ >= static_cast<std::int64_t>(kAnnounceRateLimitSec))
                    {
                        lastReannounceTime_ = nowEpochSec;
                        if (!sendAnnounce()) closeUnlocked();
                    }
                }

                if (transport_ && transport_->isConnected() && healthDue)
                {
                    lastHealthReportSec_.store(nowEpochSec, std::memory_order_relaxed);
                    std::string hLine = std::string(kHealthLinePrefix)
                        + "pcap_recv=" + std::to_string(totalPcapRecv_.load(std::memory_order_relaxed))
                        + " pcap_drop=" + std::to_string(totalPcapDrop_.load(std::memory_order_relaxed))
                        + " buf_drop="  + std::to_string(sendBufDrops_.load(std::memory_order_relaxed))
                        + " ver=" + kClientVersion
                        + " wire_proto=" + std::to_string(kWireProtoVersion)
                        + " platform=" + kClientPlatform
                        + " agg_interval_ms=" + std::to_string(aggInterval_.intervalMs())
                        + " agg_flows="       + std::to_string(aggLastFlows_)
                        + " cfg_transport="           + (transportMode_ == TransportMode::WebSocket ? "websocket" : "tcp")
                        + " cfg_compress="            + (useCompression_ ? "1" : "0")
                        + " cfg_send_buffer="         + std::to_string(cfgSendBufferBytes_)
                        + " cfg_auto_update="         + (cfgAutoUpdate_ ? "1" : "0")
                        + " cfg_reconnect_attempts="  + std::to_string(reconnectMaxAttempts_)
                        + " cfg_reconnect_interval="  + std::to_string(reconnectIntervalSec_)
                        + " cfg_agg_target="          + std::to_string(cfgAggTargetLinesPerSec_)
                        + " cfg_agg_min_ms="          + std::to_string(cfgAggMinIntervalMs_)
                        + " cfg_agg_max_ms="          + std::to_string(cfgAggMaxIntervalMs_)
                        + " cfg_agg_max_flows="       + std::to_string(aggMaxFlows_)
                        + " cfg_log_level="           + []{
                              const auto lv = globalFileLogger().currentLevel();
                              return lv == platform::LogLevel::Warn ? std::string("Warn")
                                   : lv == platform::LogLevel::Err  ? std::string("Err")
                                   : std::string("Info"); }()
                        + "\n";
                    if (!deflateAndWrite(hLine.data(), hLine.size()))
                        closeUnlocked();
                }

                if (transport_ && transport_->isConnected())
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - sessionStart_).count();
                    if (elapsed < 0) elapsed = 0;
                    if (static_cast<std::uint64_t>(elapsed) >= kMaxSessionSeconds)
                        closeUnlocked();
                }

                if (!flushBuffer_.empty() && transport_ && transport_->isConnected() &&
                    !deflateAndWrite(flushBuffer_.data(), flushBuffer_.size()))
                    closeUnlocked();
            }
            catch (const std::exception &e)
            {
                std::cerr << "ntm-client: senderLoop exception: " << e.what() << "\n";
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (...)
            {
                std::cerr << "ntm-client: senderLoop caught unknown exception\n";
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void closeUnlocked()
    {
        if (transport_) { transport_->close(); transport_.reset(); }
        deflater_.reset();  // new session may negotiate different caps
    }

    bool connectUnlocked()
    {
        if (transport_ && transport_->isConnected()) return true;

        auto logInfo = [&](const std::string &msg) {
            if (verbose_) platform::ntmLog(platform::LogLevel::Info, isDaemon_, msg);
        };
        auto logErr = [&](const std::string &msg) {
            platform::ntmLog(platform::LogLevel::Err, isDaemon_, msg);
        };

        // ── Create the appropriate transport for this attempt ────────────────
        std::unique_ptr<ITransport> t;
        if (transportMode_ == TransportMode::WebSocket)
        {
            logInfo("ntm-client: [connect] using WebSocket transport");
            t = std::make_unique<WebSocketTransport>(
                sslCtx_, tlsServerCertPath_, verbose_, isDaemon_);
        }
        else
        {
            logInfo("ntm-client: [connect] using TCP+TLS transport");
            t = std::make_unique<TcpTlsTransport>(
                sslCtx_, tlsServerCertPath_, verbose_, isDaemon_);
        }

        logInfo("ntm-client: [connect] attempting connection to "
                + host_ + ":" + std::to_string(port_));

        if (!t->connect(host_, port_, lastError_))
        {
            logErr("ntm-client: [connect] connection failed: " + lastError_);
            return false;
        }

        // ── Auth ─────────────────────────────────────────────────────────────
        std::uint8_t negotiatedCaps = kCapNone;
        if (!performClientAuth(*t, identityPath_, isDaemon_, verbose_, &lastError_,
                               useCompression_, &negotiatedCaps))
        {
            t->close();
            return false;
        }

        if (negotiatedCaps & kCapZlib)
        {
            deflater_ = std::make_unique<ZlibDeflater>();
            compBuf_.reserve(65536);
            std::cerr << "ntm-client: zlib compression enabled for this session\n";
        }
        else
        {
            deflater_.reset();
        }

        // Transport is live — make it visible to deflateAndWrite / sendAnnounce.
        transport_ = std::move(t);

        logInfo("ntm-client: [connect] sending address announce (X/A lines)...");
        if (!sendAnnounce())
        {
            const std::string err = "failed to send address announce";
            logErr("ntm-client: [connect] address announce FAILED");
            lastError_ = err;
            transport_->close();
            transport_.reset();
            deflater_.reset();
            return false;
        }

        sessionStart_ = std::chrono::steady_clock::now();
        const char *tMode = (transportMode_ == TransportMode::WebSocket)
                            ? "WebSocket" : "TCP+TLS";
        platform::ntmLog(platform::LogLevel::Info, isDaemon_,
                         std::string("ntm-client: connected to ")
                         + host_ + ":" + std::to_string(port_)
                         + " (" + tMode + ", session max 6h)");
        return true;
    }
};

// ---------------------------------------------------------------------------
// PacketSniffer
// ---------------------------------------------------------------------------

class PacketSniffer
{
public:
    PacketSniffer(std::string iface, std::string label, ClientConnection &connection)
        : iface_(std::move(iface)), label_(std::move(label)), connection_(connection) {}

    ~PacketSniffer() { stop(); }

    void start()
    {
        if (running_.load()) return;
        running_.store(true);
        worker_ = std::thread(&PacketSniffer::run, this);
    }

    void stop()
    {
        if (!running_.load()) return;
        running_.store(false);
        {
            // pcapMutex_ serialises this pcap_breakloop() against the
            // pcap_close() in run()'s teardown so the handle can never be
            // closed by one thread while breakloop'd by another.
            std::lock_guard<std::mutex> lk(pcapMutex_);
            if (pcapHandle_) pcap_breakloop(pcapHandle_);
        }
        if (worker_.joinable()) worker_.join();
    }

private:
    static void pcapCallback(u_char *user, const struct pcap_pkthdr *hdr,
                             const u_char *pkt)
    {
        reinterpret_cast<PacketSniffer *>(user)->handlePacket(hdr, pkt);
    }

    void handlePacket(const struct pcap_pkthdr *header, const u_char *packet)
    {
        if (!running_.load()) return;

        const u_char *l3 = nullptr;
        bool isV6 = false;

        switch (linkType_)
        {
        case DLT_EN10MB:
            if (header->caplen < 14) return;
            {
                auto et = static_cast<std::uint16_t>((packet[12] << 8) | packet[13]);
                if      (et == 0x0800) { isV6 = false; l3 = packet + 14; }
                else if (et == 0x86DD) { isV6 = true;  l3 = packet + 14; }
                else return;
            }
            break;
#ifdef __linux__
        case DLT_LINUX_SLL:
        case DLT_LINUX_SLL2:
            if (header->caplen < 16) return;
            {
                auto proto = static_cast<std::uint16_t>((packet[14] << 8) | packet[15]);
                if      (proto == 0x0800) { isV6 = false; l3 = packet + 16; }
                else if (proto == 0x86DD) { isV6 = true;  l3 = packet + 16; }
                else return;
            }
            break;
#endif
        default:
            return;
        }

        if (!l3) return;

        std::size_t l3Off = static_cast<std::size_t>(l3 - packet);
        if (!isV6 && header->caplen < l3Off + sizeof(ipv4_header)) return;
        if ( isV6 && header->caplen < l3Off + sizeof(ipv6_header)) return;

        char srcBuf[INET6_ADDRSTRLEN], dstBuf[INET6_ADDRSTRLEN];
        if (!isV6)
        {
            auto *h = reinterpret_cast<const ipv4_header *>(l3);
            if (!::inet_ntop(AF_INET, &h->src_addr, srcBuf, sizeof(srcBuf))) return;
            if (!::inet_ntop(AF_INET, &h->dst_addr, dstBuf, sizeof(dstBuf))) return;
        }
        else
        {
            auto *h = reinterpret_cast<const ipv6_header *>(l3);
            if (!::inet_ntop(AF_INET6, h->src_addr, srcBuf, sizeof(srcBuf))) return;
            if (!::inet_ntop(AF_INET6, h->dst_addr, dstBuf, sizeof(dstBuf))) return;
        }

        PacketMeta meta;
        meta.iface  = label_;
        meta.srcIp  = srcBuf;
        meta.dstIp  = dstBuf;
        meta.bytes  = header->len;
        connection_.accumulateFlow(meta);
    }

    void run()
    {
        // All pcap_* calls below operate on the thread-local `h`. The shared
        // member pcapHandle_ is only ever touched under pcapMutex_, purely so
        // stop() can pcap_breakloop() a handle that is guaranteed valid for the
        // duration it holds the lock. Teardown clears the member under the lock
        // *before* pcap_close(h), so breakloop and close can never overlap.
        pcap_t *h = nullptr;
        try
        {
            char errbuf[PCAP_ERRBUF_SIZE]{};
            h = pcap_create(iface_.c_str(), errbuf);
            if (!h)
            {
                std::cerr << "ntm-client: pcap_create failed for " << iface_
                          << ": " << errbuf << "\n";
                return;
            }
            pcap_set_snaplen(h, 192);
            pcap_set_promisc(h, 1);
            pcap_set_timeout(h, 10);
            pcap_set_buffer_size(h, 16 * 1024 * 1024);

            if (pcap_activate(h) < 0)
            {
                std::cerr << "ntm-client: pcap_activate failed for " << iface_
                          << ": " << pcap_geterr(h) << "\n";
                pcap_close(h);
                return;
            }

            linkType_ = pcap_datalink(h);

            struct bpf_program fp{};
            if (pcap_compile(h, &fp, "ip or ip6", 1, PCAP_NETMASK_UNKNOWN) == 0)
            {
                pcap_setfilter(h, &fp);
                pcap_freecode(&fp);
            }

            {
                std::lock_guard<std::mutex> lk(pcapMutex_);
                pcapHandle_ = h;
            }

            std::int64_t lastStatsSec = 0;
            std::uint32_t prevRecv = 0, prevDrop = 0;
            while (running_.load())
            {
                int ret = pcap_dispatch(h, -1, &PacketSniffer::pcapCallback,
                                        reinterpret_cast<u_char *>(this));
                if (ret == -1) break;

                const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                if (nowSec - lastStatsSec >= 30)
                {
                    lastStatsSec = nowSec;
                    struct pcap_stat ps{};
                    if (pcap_stats(h, &ps) == 0)
                    {
                        connection_.addPcapStats(
                            static_cast<std::uint32_t>(ps.ps_recv - prevRecv),
                            static_cast<std::uint32_t>(ps.ps_drop - prevDrop));
                        prevRecv = ps.ps_recv;
                        prevDrop = ps.ps_drop;
                    }
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "ntm-client: PacketSniffer exception: " << e.what() << "\n";
        }
        catch (...)
        {
            std::cerr << "ntm-client: PacketSniffer unknown exception\n";
        }
        {
            std::lock_guard<std::mutex> lk(pcapMutex_);
            pcapHandle_ = nullptr;
        }
        if (h) pcap_close(h);
    }

    std::string       iface_;   // pcap device name (passed to pcap_create)
    std::string       label_;   // human-readable label sent in D lines
    ClientConnection &connection_;
    std::atomic<bool> running_{false};
    std::thread       worker_;
    std::mutex        pcapMutex_;              // guards pcapHandle_
    pcap_t           *pcapHandle_{nullptr};    // only touched under pcapMutex_
    int               linkType_{DLT_EN10MB};
};

// ---------------------------------------------------------------------------
// runClient
// ---------------------------------------------------------------------------

static std::atomic<bool> g_running{true};

int runClient(bool daemonMode, const ClientConfig &config, char **argv)
{
    platform::initPlatform();
    platform::setupSignals(g_running);
    platform::daemonize(daemonMode);

    const char *id = config.identityPath.empty()      ? "(none)" : config.identityPath.c_str();
    const char *ca = config.tlsCaPath.empty()          ? "(none)" : config.tlsCaPath.c_str();
    const char *sc = config.tlsServerCertPath.empty()  ? "(none)" : config.tlsServerCertPath.c_str();

    const char *tMode = (config.transport == TransportMode::WebSocket)
                        ? "websocket" : "tcp";

    std::string msg = "ntm-client: connecting to " + config.server
                    + ":" + std::to_string(config.port)
                    + " (transport=" + tMode
                    + ", identity=" + id + ", ca=" + ca + ", server-cert=" + sc + ")";
    platform::ntmLog(platform::LogLevel::Info, daemonMode, msg);

    // Refuse to run without TLS. With neither a CA bundle nor a pinned server
    // cert, the client would connect in cleartext and send its identity and all
    // captured metadata unencrypted. The server mandates TLS so such a client
    // can never succeed anyway; fail loudly instead of silently going plaintext.
    if (config.tlsCaPath.empty() && config.tlsServerCertPath.empty())
    {
        platform::ntmLog(platform::LogLevel::Err, daemonMode,
            "ntm-client: refusing to start without TLS — set 'ca' (CA bundle) "
            "or 'server_cert' (pinned cert) in the config / --ca / --server-cert");
        platform::cleanupPlatform();
        return 1;
    }

    {
        char rbuf[128];
        std::snprintf(rbuf, sizeof(rbuf),
            "ntm-client: reconnect policy: max %u attempt(s), interval %us",
            config.reconnectMaxAttempts, config.reconnectIntervalSec);
        platform::ntmLog(platform::LogLevel::Info, daemonMode, rbuf);
    }

    AdaptiveInterval::Config aggCfg;
    aggCfg.targetLinesPerSec = config.aggTargetLinesPerSec;
    aggCfg.minIntervalMs     = config.aggMinIntervalMs;
    aggCfg.maxIntervalMs     = config.aggMaxIntervalMs;

    ClientConnection connection(config.server, config.port,
                                config.identityPath, config.tlsCaPath,
                                config.tlsServerCertPath,
                                config.sendBufferBytes,
                                config.externalIpUrl, config.externalIpTimeoutMs,
                                &g_running,
                                config.reconnectMaxAttempts,
                                config.reconnectIntervalSec,
                                aggCfg,
                                config.aggMaxFlows,
                                config.useCompression,
                                daemonMode,
                                config.verbose,
                                config.transport,
                                config.auto_update);
    connection.setCfg(config);

    // Enumerate capturable devices. Returns false only when pcap_findalldevs
    // itself errors (hard failure at startup); an empty result is valid and
    // simply means "nothing to capture yet" — a NIC appearing later will be
    // picked up by the periodic re-scan below (O3).
    auto enumerateDesired =
        [](std::unordered_map<std::string, std::string> &out) -> bool
    {
        out.clear();
        pcap_if_t *alldevs = nullptr;
        char errbuf[PCAP_ERRBUF_SIZE]{};
        if (pcap_findalldevs(&alldevs, errbuf) != 0)
            return false;
        for (pcap_if_t *d = alldevs; d; d = d->next)
        {
            if (!d->name) continue;
            if (platform::isLoopbackIface(reinterpret_cast<platform::pcap_if *>(d))) continue;
            if (!d->addresses) continue;
            // Human-readable description as the wire label (e.g. "Intel Ethernet
            // Connection" instead of "\Device\NPF_{GUID}" on Windows); fall back
            // to the raw device name (typical on Linux). Spaces -> '-' so the
            // label is safe for the space-delimited "D <iface> ..." protocol.
            std::string label = (d->description && d->description[0])
                                ? std::string(d->description)
                                : std::string(d->name);
            for (char &c : label) if (c == ' ') c = '-';
            out.emplace(std::string(d->name), std::move(label));
        }
        if (alldevs) pcap_freealldevs(alldevs);
        return true;
    };

    std::unordered_map<std::string, std::unique_ptr<PacketSniffer>> sniffers;

    // Reconcile running sniffers with the desired device set: stop+drop sniffers
    // whose device disappeared, start sniffers for newly appeared devices.
    auto syncSniffers =
        [&](const std::unordered_map<std::string, std::string> &desired)
    {
        for (auto it = sniffers.begin(); it != sniffers.end(); )
        {
            if (desired.find(it->first) == desired.end())
            {
                if (it->second) it->second->stop();
                it = sniffers.erase(it);
            }
            else
            {
                ++it;
            }
        }
        for (const auto &kv : desired)
        {
            if (sniffers.find(kv.first) != sniffers.end()) continue;
            auto s = std::make_unique<PacketSniffer>(kv.first, kv.second, connection);
            s->start();
            sniffers.emplace(kv.first, std::move(s));
        }
    };

    std::unordered_map<std::string, std::string> desired;
    if (!enumerateDesired(desired))
    {
        platform::ntmLog(platform::LogLevel::Err, daemonMode,
                         "ntm-client: pcap_findalldevs failed");
        platform::cleanupPlatform();
        return 1;
    }
    syncSniffers(desired);

    startAutoUpdater(config, argv);

    // Re-scan periodically so NICs that appear or disappear after startup
    // (VPN up/down, USB adapter, Wi-Fi toggle) are captured/released without
    // restarting the client.
    int sinceScanSec = 0;
    while (g_running.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_running.load()) break;
        if (++sinceScanSec < 30) continue;
        sinceScanSec = 0;
        std::unordered_map<std::string, std::string> d2;
        if (enumerateDesired(d2))   // ignore transient enumeration failures
            syncSniffers(d2);
    }

    stopAutoUpdater();
    for (auto &kv : sniffers) if (kv.second) kv.second->stop();
    sniffers.clear();
    connection.close();
    platform::cleanupPlatform();
    return 0;
}

} // namespace ntm
