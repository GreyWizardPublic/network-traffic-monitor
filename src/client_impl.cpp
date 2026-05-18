#include "client.hpp"
#include "client_core.hpp"
#include "client_platform.hpp"
#include "proto_client_server.hpp"

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
                     unsigned externalIpTimeoutMs = 5000)
        : host_(std::move(host)), port_(port)
        , identityPath_(std::move(identityPath))
        , tlsCaPath_(std::move(tlsCaPath))
        , tlsServerCertPath_(std::move(tlsServerCertPath))
        , externalIpUrl_(std::move(externalIpUrl))
        , externalIpTimeoutMs_(externalIpTimeoutMs)
    {
        std::size_t bufSize =
            (sendBufferBytes >= kSendBufferMinBytes && sendBufferBytes <= kMaxIOBytes)
            ? sendBufferBytes : kSendBufferDefaultBytes;
        sendBuffer_.resize(bufSize);
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

    const std::string &lastError() const { return lastError_; }

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
    std::vector<char>        sendBuffer_;
    std::size_t              contentEnd_{0};
    std::condition_variable  queueCv_;
    std::atomic<bool>        runningSender_{false};
    std::thread              senderThread_;

    std::mutex               connectionMutex_;
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
                }

                const bool netChanged = netMonitor_.checkAndClear();
                const auto nowEpochSec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                const bool healthDue =
                    (nowEpochSec - lastHealthReportSec_.load(std::memory_order_relaxed)) >= 30;
                if (toSend == 0 && !netChanged && !healthDue) continue;

                std::lock_guard<std::mutex> connLock(connectionMutex_);
                if (!platform::sockValid(fd_))
                {
                    if (!connectUnlocked()) continue;
                }

                if (platform::sockValid(fd_) && netChanged)
                {
                    if (nowEpochSec - lastReannounceTime_ >= 30)
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
                    !platform::writeExact(ssl_, fd_, sendBuffer_.data(), toSend))
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
        if (pcapHandle_) pcap_breakloop(pcapHandle_);
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
        try
        {
            char errbuf[PCAP_ERRBUF_SIZE]{};
            pcapHandle_ = pcap_create(iface_.c_str(), errbuf);
            if (!pcapHandle_)
            {
                std::cerr << "ntm-client: pcap_create failed for " << iface_
                          << ": " << errbuf << "\n";
                return;
            }
            pcap_set_snaplen(pcapHandle_, 192);
            pcap_set_promisc(pcapHandle_, 1);
            pcap_set_timeout(pcapHandle_, 10);
            pcap_set_buffer_size(pcapHandle_, 16 * 1024 * 1024);

            if (pcap_activate(pcapHandle_) < 0)
            {
                std::cerr << "ntm-client: pcap_activate failed for " << iface_
                          << ": " << pcap_geterr(pcapHandle_) << "\n";
                pcap_close(pcapHandle_);
                pcapHandle_ = nullptr;
                return;
            }

            linkType_ = pcap_datalink(pcapHandle_);

            struct bpf_program fp{};
            if (pcap_compile(pcapHandle_, &fp, "ip or ip6", 1, PCAP_NETMASK_UNKNOWN) == 0)
            {
                pcap_setfilter(pcapHandle_, &fp);
                pcap_freecode(&fp);
            }

            std::int64_t lastStatsSec = 0;
            std::uint32_t prevRecv = 0, prevDrop = 0;
            while (running_.load())
            {
                int ret = pcap_dispatch(pcapHandle_, -1, &PacketSniffer::pcapCallback,
                                        reinterpret_cast<u_char *>(this));
                if (ret == -1) break;

                const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                if (nowSec - lastStatsSec >= 30)
                {
                    lastStatsSec = nowSec;
                    struct pcap_stat ps{};
                    if (pcap_stats(pcapHandle_, &ps) == 0)
                    {
                        connection_.addPcapStats(
                            static_cast<std::uint32_t>(ps.ps_recv - prevRecv),
                            static_cast<std::uint32_t>(ps.ps_drop - prevDrop));
                        prevRecv = ps.ps_recv;
                        prevDrop = ps.ps_drop;
                    }
                }
            }
            pcap_close(pcapHandle_);
            pcapHandle_ = nullptr;
        }
        catch (const std::exception &e)
        {
            std::cerr << "ntm-client: PacketSniffer exception: " << e.what() << "\n";
            if (pcapHandle_) { pcap_close(pcapHandle_); pcapHandle_ = nullptr; }
        }
        catch (...)
        {
            std::cerr << "ntm-client: PacketSniffer unknown exception\n";
            if (pcapHandle_) { pcap_close(pcapHandle_); pcapHandle_ = nullptr; }
        }
    }

    std::string       iface_;   // pcap device name (passed to pcap_create)
    std::string       label_;   // human-readable label sent in D lines
    ClientConnection &connection_;
    std::atomic<bool> running_{false};
    std::thread       worker_;
    pcap_t           *pcapHandle_{nullptr};
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

    ClientConnection connection(config.server, config.port,
                                config.identityPath, config.tlsCaPath,
                                config.tlsServerCertPath,
                                config.sendBufferBytes,
                                config.externalIpUrl, config.externalIpTimeoutMs);
    if (!connection.connectOnce())
    {
        const std::string &err = connection.lastError();
        platform::ntmLog(platform::LogLevel::Err, daemonMode,
                         "ntm-client: failed to connect: " + (err.empty() ? "unknown" : err));
        platform::cleanupPlatform();
        return 1;
    }

    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE]{};
    if (pcap_findalldevs(&alldevs, errbuf) != 0 || !alldevs)
    {
        platform::ntmLog(platform::LogLevel::Err, daemonMode,
                         std::string("ntm-client: pcap_findalldevs failed: ")
                         + (errbuf[0] ? errbuf : "no devices"));
        platform::cleanupPlatform();
        return 1;
    }

    std::vector<std::unique_ptr<PacketSniffer>> sniffers;
    for (pcap_if_t *d = alldevs; d; d = d->next)
    {
        if (!d->name) continue;
        if (platform::isLoopbackIface(reinterpret_cast<platform::pcap_if *>(d))) continue;
        if (!d->addresses) continue;
        // Use the human-readable description as the display label (e.g. "Intel Ethernet
        // Connection" instead of "\Device\NPF_{GUID}" on Windows). Fall back to the
        // raw device name when no description is available (typical on Linux).
        // Replace spaces with '-' so the label is safe for the whitespace-delimited
        // wire protocol: "D <iface> <src> <dst> <bytes>\n".
        std::string label = (d->description && d->description[0])
                            ? std::string(d->description)
                            : std::string(d->name);
        for (char &c : label) if (c == ' ') c = '-';
        auto sniffer = std::make_unique<PacketSniffer>(std::string(d->name), std::move(label), connection);
        sniffer->start();
        sniffers.push_back(std::move(sniffer));
    }
    pcap_freealldevs(alldevs);

    while (g_running.load())
        std::this_thread::sleep_for(std::chrono::seconds(1));

    for (auto &s : sniffers) if (s) s->stop();
    connection.close();
    platform::cleanupPlatform();
    return 0;
}

} // namespace ntm
