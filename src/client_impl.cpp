#include "client.hpp"
#include "client_core.hpp"
#include "client_platform.hpp"
#include "proto_client_server.hpp"
#include "version.hpp"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

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

using platform::SockFd;
using platform::kInvalidSock;

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
                     unsigned reconnectIntervalSec = 60)
        : host_(std::move(host)), port_(port)
        , identityPath_(std::move(identityPath))
        , tlsCaPath_(std::move(tlsCaPath))
        , tlsServerCertPath_(std::move(tlsServerCertPath))
        , externalIpUrl_(std::move(externalIpUrl))
        , externalIpTimeoutMs_(externalIpTimeoutMs)
        , reconnectMaxAttempts_(reconnectMaxAttempts)
        , reconnectIntervalSec_(reconnectIntervalSec)
        , g_runningPtr_(gRunning)
    {
        std::size_t bufSize =
            (sendBufferBytes >= kSendBufferMinBytes && sendBufferBytes <= kMaxIOBytes)
            ? sendBufferBytes : kSendBufferDefaultBytes;
        sendBuffer_.resize(bufSize);
        flushBuffer_.resize(bufSize);
        contentEnd_ = 0;

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

    void sendPacket(const PacketMeta &meta)
    {
        thread_local char buf[256];
        int len = std::snprintf(buf, sizeof(buf), "D %.64s %.46s %.46s %u\n",
                                meta.iface.c_str(), meta.srcIp.c_str(),
                                meta.dstIp.c_str(), meta.bytes);
        if (len <= 0 || static_cast<std::size_t>(len) > sizeof(buf)) return;
        std::size_t lineLen = static_cast<std::size_t>(len);
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (contentEnd_ > sendBuffer_.size()) return;
            if (lineLen > sendBuffer_.size() - contentEnd_)
            {
                sendBufDrops_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            std::memcpy(sendBuffer_.data() + contentEnd_, buf, lineLen);
            contentEnd_ += lineLen;
            if (contentEnd_ >= kSendBatchSize) queueCv_.notify_one();
        }
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

    mutable std::mutex       connectionMutex_;
    std::string              host_;
    std::uint16_t            port_;
    SockFd                   fd_{kInvalidSock};
    SSL_CTX                 *sslCtx_{nullptr};
    SSL                     *ssl_{nullptr};
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

    platform::NetworkMonitor netMonitor_;

    bool sendAnnounce(SSL *ssl, SockFd fd)
    {
        auto lanAddrs = platform::collectLanAddresses();
        if (lanAddrs.empty()) return true;

        std::string extIp = platform::queryExternalIP(externalIpUrl_, externalIpTimeoutMs_);
        std::string xLine = std::string(kExtIPLinePrefix)
                          + (extIp.empty() ? kExtIPNull : extIp) + '\n';
        if (!platform::writeExact(ssl, fd, xLine.data(), xLine.size())) return false;

        for (const auto &ip : lanAddrs)
        {
            std::string aLine = std::string(kAddrLinePrefix) + ip + '\n';
            if (!platform::writeExact(ssl, fd, aLine.data(), aLine.size())) return false;
        }

        lastReannounceTime_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return true;
    }

    void senderLoop()
    {
        while (runningSender_.load())
        {
            try
            {
                std::size_t toSend = 0;
                {
                    std::unique_lock<std::mutex> lock(queueMutex_);
                    queueCv_.wait_for(lock, std::chrono::milliseconds(kSenderWakeMs), [this] {
                        return !runningSender_.load() || contentEnd_ >= kSendBatchSize;
                    });
                    if (!runningSender_.load()) break;
                    toSend = contentEnd_;
                    contentEnd_ = 0;
                    // Swap buffers so sniffers can fill sendBuffer_ immediately
                    // while the sender reads from flushBuffer_ without holding the lock.
                    if (toSend > 0) std::swap(sendBuffer_, flushBuffer_);
                }

                const bool netChanged = netMonitor_.checkAndClear();
                const auto nowEpochSec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                const bool healthDue =
                    (nowEpochSec - lastHealthReportSec_.load(std::memory_order_relaxed)) >=
                    static_cast<std::int64_t>(kHealthIntervalSec);
                if (toSend == 0 && !netChanged && !healthDue) continue;

                std::lock_guard<std::mutex> connLock(connectionMutex_);
                if (!platform::sockValid(fd_))
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
                }

                if (platform::sockValid(fd_) && netChanged)
                {
                    if (nowEpochSec - lastReannounceTime_ >= static_cast<std::int64_t>(kAnnounceRateLimitSec))
                    {
                        lastReannounceTime_ = nowEpochSec;
                        if (!sendAnnounce(ssl_, fd_)) closeUnlocked();
                    }
                }

                if (platform::sockValid(fd_) && healthDue)
                {
                    lastHealthReportSec_.store(nowEpochSec, std::memory_order_relaxed);
                    std::string hLine = std::string(kHealthLinePrefix)
                        + "pcap_recv=" + std::to_string(totalPcapRecv_.load(std::memory_order_relaxed))
                        + " pcap_drop=" + std::to_string(totalPcapDrop_.load(std::memory_order_relaxed))
                        + " buf_drop="  + std::to_string(sendBufDrops_.load(std::memory_order_relaxed))
                        + " ver=" + kNtmVersion
                        + "\n";
                    if (!platform::writeExact(ssl_, fd_, hLine.data(), hLine.size()))
                        closeUnlocked();
                }

                if (platform::sockValid(fd_))
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - sessionStart_).count();
                    if (elapsed < 0) elapsed = 0;
                    if (static_cast<std::uint64_t>(elapsed) >= kMaxSessionSeconds)
                        closeUnlocked();
                }

                if (toSend > 0 && platform::sockValid(fd_) &&
                    !platform::writeExact(ssl_, fd_, flushBuffer_.data(), toSend))
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
        if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (platform::sockValid(fd_)) { platform::closeSocket(fd_); fd_ = kInvalidSock; }
    }

    bool connectUnlocked()
    {
        if (platform::sockValid(fd_)) return true;

        SockFd fd = platform::connectToServer(host_, port_, lastError_);
        if (!platform::sockValid(fd)) return false;

        platform::setSendBufferSize(fd, 4 * 1024 * 1024);

        SSL *ssl = nullptr;
        if (sslCtx_)
        {
            ssl = SSL_new(sslCtx_);
            if (!ssl)
            {
                lastError_ = "SSL_new failed";
                platform::closeSocket(fd);
                return false;
            }
            // SNI: only for DNS hostnames, not IP literals (RFC 6066)
            {
                unsigned char ipBuf[16];
                const bool isIp = (::inet_pton(AF_INET,  host_.c_str(), ipBuf) == 1) ||
                                  (::inet_pton(AF_INET6, host_.c_str(), ipBuf) == 1);
                if (!isIp) SSL_set_tlsext_host_name(ssl, host_.c_str());
            }
#ifdef _WIN32
            SSL_set_fd(ssl, static_cast<int>(fd));
#else
            SSL_set_fd(ssl, fd);
#endif
            if (SSL_connect(ssl) != 1)
            {
                lastError_ = "TLS handshake failed";
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                platform::closeSocket(fd);
                return false;
            }
            if (!verifyServerIdentityAndPin(ssl, host_, tlsServerCertPath_,
                                            false, false))
            {
                lastError_ = "server identity verification failed";
                SSL_free(ssl);
                platform::closeSocket(fd);
                return false;
            }
        }

        if (!performClientAuth(ssl, static_cast<std::uintptr_t>(fd),
                               identityPath_, false, false, &lastError_))
        {
            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            platform::closeSocket(fd);
            return false;
        }

        if (!sendAnnounce(ssl, fd))
        {
            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            platform::closeSocket(fd);
            lastError_ = "failed to send address announce";
            return false;
        }

        fd_ = fd;
        ssl_ = ssl;
        sessionStart_ = std::chrono::steady_clock::now();
        std::cerr << "ntm-client: connected to " << host_ << ":" << port_
                  << (ssl ? " (TLS, session max 6h)" : " (plain)") << "\n";
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
        connection_.sendPacket(meta);
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

int runClient(bool daemonMode, const ClientConfig &config)
{
    platform::initPlatform();
    platform::setupSignals(g_running);
    platform::daemonize(daemonMode);

    const char *id = config.identityPath.empty()      ? "(none)" : config.identityPath.c_str();
    const char *ca = config.tlsCaPath.empty()          ? "(none)" : config.tlsCaPath.c_str();
    const char *sc = config.tlsServerCertPath.empty()  ? "(none)" : config.tlsServerCertPath.c_str();

    std::string msg = "ntm-client: connecting to " + config.server
                    + ":" + std::to_string(config.port)
                    + " (identity=" + id + ", ca=" + ca + ", server-cert=" + sc + ")";
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

    ClientConnection connection(config.server, config.port,
                                config.identityPath, config.tlsCaPath,
                                config.tlsServerCertPath,
                                config.sendBufferBytes,
                                config.externalIpUrl, config.externalIpTimeoutMs,
                                &g_running,
                                config.reconnectMaxAttempts,
                                config.reconnectIntervalSec);

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

    for (auto &kv : sniffers) if (kv.second) kv.second->stop();
    sniffers.clear();
    connection.close();
    platform::cleanupPlatform();
    return 0;
}

} // namespace ntm
