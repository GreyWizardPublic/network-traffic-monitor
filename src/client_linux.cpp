#if !defined(__linux__)
#error "client_linux.cpp is only for Linux builds"
#endif

#include "client.hpp"
#include "proto_client_server.hpp"

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace ntm
{

// Simple IPv4 header struct for parsing.
struct ipv4_header
{
    std::uint8_t version_ihl;
    std::uint8_t tos;
    std::uint16_t total_length;
    std::uint16_t id;
    std::uint16_t frag_off;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t checksum;
    std::uint32_t src_addr;
    std::uint32_t dst_addr;
};

// Minimal IPv6 header for parsing addresses.
struct ipv6_header
{
    std::uint32_t ver_tc_fl;
    std::uint16_t payload_len;
    std::uint8_t next_header;
    std::uint8_t hop_limit;
    std::uint8_t src_addr[16];
    std::uint8_t dst_addr[16];
};

// Max single I/O chunk for readExact/writeExact (avoids int overflow and unreasonable allocations).
inline constexpr std::size_t kMaxIOBytes = 2 * 1024 * 1024;

static bool g_verbose = false;
static bool g_daemon = false;

// Read exactly n bytes (via SSL or raw fd). Returns true on success. n must be <= kMaxIOBytes.
static bool readExact(SSL *ssl, int fd, void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes)
        return false;
    std::uint8_t *p = static_cast<std::uint8_t *>(buf);
    while (n > 0)
    {
        int chunk = static_cast<int>(n < static_cast<std::size_t>(INT_MAX) ? n : static_cast<std::size_t>(INT_MAX));
        int r = ssl ? SSL_read(ssl, p, chunk) : static_cast<int>(::recv(fd, p, chunk, 0));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

// Write exactly n bytes (via SSL or raw fd). Returns true on success. n must be <= kMaxIOBytes.
static bool writeExact(SSL *ssl, int fd, const void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes)
        return false;
    const std::uint8_t *p = static_cast<const std::uint8_t *>(buf);
    while (n > 0)
    {
        int chunk = static_cast<int>(n < static_cast<std::size_t>(INT_MAX) ? n : static_cast<std::size_t>(INT_MAX));
        int r = ssl ? SSL_write(ssl, p, chunk) : static_cast<int>(::send(fd, p, chunk, MSG_NOSIGNAL));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

// M6: warn (not fatal) if the private identity key file is group/world-readable
// or owned by another user. Mirrors what ssh does for ~/.ssh/id_*.
static void checkIdentityFilePermissions(const std::string &path)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0)
        return;  // performClientAuth() will report fopen failure separately.
    const mode_t openBits = st.st_mode & (S_IRWXG | S_IRWXO);
    const bool groupWorldReadable = (openBits & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH | S_IXGRP | S_IXOTH)) != 0;
    if (groupWorldReadable)
    {
        const char *msg = "ntm-client: WARNING: identity key has group/world permissions; "
                          "tighten with 'chmod 600' (read by others is a credential leak)";
        if (g_daemon)
            syslog(LOG_WARNING, "%s (path=%s mode=%04o)", msg, path.c_str(),
                   static_cast<unsigned>(st.st_mode & 07777));
        else
            std::cerr << msg << " (path=" << path << " mode="
                      << std::oct << (st.st_mode & 07777) << std::dec << ")\n";
    }
    if (st.st_uid != ::geteuid())
    {
        const char *msg = "ntm-client: WARNING: identity key is not owned by the current user";
        if (g_daemon)
            syslog(LOG_WARNING, "%s (path=%s)", msg, path.c_str());
        else
            std::cerr << msg << " (path=" << path << ")\n";
    }
}

// Perform Ed25519 auth after TCP (and optional TLS) connect. Returns true if server accepted.
// If errOut is non-null, set it to a short reason on failure.
static bool performClientAuth(int fd, SSL *ssl, const std::string &identityPath, std::string *errOut = nullptr)
{
    auto setErr = [&errOut](const char *msg) { if (errOut) *errOut = msg; };
    if (identityPath.empty())
        return true;

    checkIdentityFilePermissions(identityPath);

    FILE *fp = std::fopen(identityPath.c_str(), "r");
    if (!fp)
    {
        setErr("cannot open identity file");
        std::cerr << "ntm-client: cannot open identity file: " << identityPath << "\n";
        return false;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    if (!pkey)
    {
        setErr("failed to read Ed25519 private key");
        std::cerr << "ntm-client: failed to read Ed25519 private key from " << identityPath << "\n";
        return false;
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519)
    {
        setErr("identity key must be Ed25519");
        std::cerr << "ntm-client: identity key must be Ed25519\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::size_t pubLen = kAuthPubkeyLen;
    std::uint8_t pubkey[kAuthPubkeyLen];
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubLen) != 1 || pubLen != kAuthPubkeyLen)
    {
        setErr("failed to get public key");
        std::cerr << "ntm-client: failed to get public key\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    // Auth v2: client initiates with version, server replies with nonce, then client signs prefix+nonce.
    std::uint8_t version = static_cast<std::uint8_t>(kAuthVersionV2);
    if (!writeExact(ssl, fd, &version, 1))
    {
        setErr("failed to send auth version");
        std::cerr << "ntm-client: failed to send auth version\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::uint8_t nonce[kAuthNonceLen];
    if (!readExact(ssl, fd, nonce, sizeof(nonce)))
    {
        setErr("failed to read auth nonce");
        std::cerr << "ntm-client: failed to read auth nonce\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::string toSign(reinterpret_cast<const char *>(kAuthSignPrefixV2), kAuthSignPrefixV2Len);
    toSign.append(reinterpret_cast<const char *>(nonce), sizeof(nonce));

    std::size_t sigLen = kAuthSignatureLen;
    std::uint8_t sig[kAuthSignatureLen];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
              && EVP_DigestSign(ctx, sig, &sigLen,
                                reinterpret_cast<const unsigned char *>(toSign.data()), toSign.size()) == 1
              && sigLen == kAuthSignatureLen;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok)
    {
        setErr("Ed25519 sign failed");
        std::cerr << "ntm-client: Ed25519 sign failed\n";
        return false;
    }

    std::uint8_t msg[kAuthPubkeyLen + kAuthSignatureLen];
    std::memcpy(msg, pubkey, kAuthPubkeyLen);
    std::memcpy(msg + kAuthPubkeyLen, sig, kAuthSignatureLen);

    if (!writeExact(ssl, fd, msg, sizeof(msg)))
    {
        setErr("failed to send auth message");
        std::cerr << "ntm-client: failed to send auth message\n";
        return false;
    }

    std::uint8_t result = 0xff;
    if (!readExact(ssl, fd, &result, 1) || result != 0x00)
    {
        setErr("server rejected authentication (key not in server allowed list?)");
        std::cerr << "ntm-client: server rejected authentication\n";
        return false;
    }
    return true;
}

static SSL_CTX *createClientTLSContext(const std::string &caPath, const std::string &serverCertPath)
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        return nullptr;
    const bool useCaVerify = !caPath.empty();
    SSL_CTX_set_verify(ctx, useCaVerify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    if (useCaVerify)
    {
        if (SSL_CTX_load_verify_locations(ctx, caPath.c_str(), nullptr) != 1)
        {
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

static X509 *loadPemCert(const std::string &path)
{
    if (path.empty())
        return nullptr;
    FILE *fp = std::fopen(path.c_str(), "r");
    if (!fp)
        return nullptr;
    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    return cert;
}

static bool sha256Fingerprint(const X509 *cert, unsigned char out[32])
{
    unsigned int n = 0;
    return cert && X509_digest(cert, EVP_sha256(), out, &n) == 1 && n == 32;
}

static bool verifyServerIdentityAndPin(SSL *ssl, const std::string &host, const std::string &pinnedServerCertPath)
{
    if (!ssl)
        return false;

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer)
    {
        if (g_verbose)
        {
            const char *msg = "no peer certificate presented by server";
            if (g_daemon)
                syslog(LOG_ERR, "ntm-client: %s", msg);
            else
                std::cerr << "ntm-client: " << msg << "\n";
        }
        return false;
    }

    bool ok = true;

    // Hostname / IP verification (independent of CA verification).
    if (!host.empty())
    {
        // If host looks like an IP, verify as IP; else verify as DNS name.
        unsigned char buf[16];
        if (::inet_pton(AF_INET, host.c_str(), buf) == 1 || ::inet_pton(AF_INET6, host.c_str(), buf) == 1)
            ok = (X509_check_ip_asc(peer, host.c_str(), 0) == 1);
        else
            ok = (X509_check_host(peer, host.c_str(), 0, 0, nullptr) == 1);

        if (g_verbose && !ok)
        {
            if (g_daemon)
                syslog(LOG_ERR, "ntm-client: server certificate hostname/IP check failed for host=%s", host.c_str());
            else
                std::cerr << "ntm-client: server certificate hostname/IP check failed for host=" << host << "\n";
        }
    }

    // Optional pinning: compare SHA-256 fingerprint of leaf certificate.
    if (ok && !pinnedServerCertPath.empty())
    {
        X509 *pinned = loadPemCert(pinnedServerCertPath);
        if (!pinned)
        {
            ok = false;
        }
        else
        {
            unsigned char a[32]{}, b[32]{};
            ok = sha256Fingerprint(peer, a) && sha256Fingerprint(pinned, b) && std::memcmp(a, b, 32) == 0;
            X509_free(pinned);
            if (g_verbose && !ok)
            {
                if (g_daemon)
                    syslog(LOG_ERR, "ntm-client: server certificate fingerprint mismatch (pinning failed)");
                else
                    std::cerr << "ntm-client: server certificate fingerprint mismatch (pinning failed)\n";
            }
        }
    }

    X509_free(peer);
    return ok;
}

// Sender wake interval; notify when buffer has at least this much data.
inline constexpr std::size_t kSendBatchSize = 8192;
inline constexpr unsigned kSenderWakeMs = 5;
// Default and bounds for fixed send buffer (configurable via config file).
inline constexpr std::size_t kSendBufferDefaultBytes = 512 * 1024;
inline constexpr std::size_t kSendBufferMinBytes = 4096;
// Config file limits to prevent memory DoS from malicious or malformed config.
inline constexpr std::size_t kMaxConfigLineLen = 8192;
inline constexpr std::size_t kMaxConfigValueLen = 2048;

// Parse one key=value line; trim key and value. Returns true if key was recognized and out updated.
// Value length is capped at kMaxConfigValueLen to bound memory.
static bool parseConfigLine(const std::string &key, const std::string &val,
                            ClientConfig &out)
{
    std::string v = val.size() <= kMaxConfigValueLen ? val : val.substr(0, kMaxConfigValueLen);
    if (key == "server")
    {
        out.server = v;
        return true;
    }
    if (key == "port")
    {
        try
        {
            unsigned long p = std::stoul(v);
            if (p != 0 && p <= 65535)
                out.port = static_cast<std::uint16_t>(p);
        }
        catch (const std::exception &) {}
        return true;
    }
    if (key == "identity")
    {
        out.identityPath = v;
        return true;
    }
    if (key == "ca")
    {
        out.tlsCaPath = v;
        return true;
    }
    if (key == "server_cert")
    {
        out.tlsServerCertPath = v;
        return true;
    }
    if (key == "send_buffer_bytes")
    {
        try
        {
            unsigned long n = std::stoul(v);
            if (n < kSendBufferMinBytes)
                n = kSendBufferMinBytes;
            if (n > kMaxIOBytes)
                n = kMaxIOBytes;
            out.sendBufferBytes = static_cast<std::size_t>(n);
        }
        catch (const std::exception &) {}
        return true;
    }
    if (key == "verbose")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        out.verbose = (lower == "1" || lower == "true" || lower == "yes");
        return true;
    }
    return false;
}

// Load all client options from one config file. Format: key=value, # comment.
// Line length capped at kMaxConfigLineLen to prevent memory DoS. Returns true if file was read.
bool loadClientConfig(const std::string &configPath, ClientConfig &out)
{
    std::ifstream f(configPath);
    if (!f)
        return false;
    std::string line;
    while (std::getline(f, line))
    {
        // Cap oversized lines to bound memory use from malformed files.
        if (line.size() > kMaxConfigLineLen)
            line.resize(kMaxConfigLineLen);
        // Strip trailing \r for Windows-style (CRLF) line endings.
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#')
            continue;
        std::size_t eq = line.find('=', start);
        if (eq == std::string::npos)
            continue;
        std::string key = line.substr(start, eq - start);
        std::size_t keyEnd = key.find_last_not_of(" \t");
        if (keyEnd != std::string::npos && keyEnd < key.size())
            key.resize(keyEnd + 1);
        std::string val = line.substr(eq + 1);
        std::size_t valStart = val.find_first_not_of(" \t");
        if (valStart != std::string::npos)
            val = val.substr(valStart);
        parseConfigLine(key, val, out);
    }
    return true;
}

class ClientConnection
{
public:
    ClientConnection(std::string host, std::uint16_t port, std::string identityPath = {},
                    std::string tlsCaPath = {}, std::string tlsServerCertPath = {},
                    std::size_t sendBufferBytes = 0)
        : host_(std::move(host)), port_(port), identityPath_(std::move(identityPath))
        , tlsCaPath_(std::move(tlsCaPath)), tlsServerCertPath_(std::move(tlsServerCertPath))
    {
        std::size_t bufSize = (sendBufferBytes >= kSendBufferMinBytes && sendBufferBytes <= kMaxIOBytes)
            ? sendBufferBytes : kSendBufferDefaultBytes;
        sendBuffer_.resize(bufSize);
        contentEnd_ = 0;

        if (!tlsCaPath_.empty() || !tlsServerCertPath_.empty())
        {
            sslCtx_ = createClientTLSContext(tlsCaPath_, tlsServerCertPath_);
            if (!sslCtx_)
            {
                std::cerr << "ntm-client: failed to create TLS context (check --ca / --server-cert)\n";
                ERR_print_errors_fp(stderr);
            }
        }
        runningSender_.store(true);
        senderThread_ = std::thread(&ClientConnection::senderLoop, this);
    }

    ~ClientConnection()
    {
        close();
        if (sslCtx_)
        {
            SSL_CTX_free(sslCtx_);
            sslCtx_ = nullptr;
        }
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
        runningSender_.store(false);
        queueCv_.notify_all();
        if (senderThread_.joinable())
            senderThread_.join();
        std::lock_guard<std::mutex> lock(connectionMutex_);
        closeUnlocked();
    }

    // Hot path: format into thread-local buffer, append in place to fixed buffer. No reallocation.
    // contentEnd_ tracks valid bytes; never read/write beyond buffer_.size().
    void sendPacket(const PacketMeta &meta)
    {
        thread_local char buf[256];
        int len = std::snprintf(buf, sizeof(buf), "D %.64s %.46s %.46s %u\n",
                               meta.iface.c_str(), meta.srcIp.c_str(), meta.dstIp.c_str(), meta.bytes);
        if (len <= 0 || static_cast<std::size_t>(len) > sizeof(buf))
            return;
        std::size_t lineLen = static_cast<std::size_t>(len);
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            // Overflow-safe: ensure no wrap in (contentEnd_ + lineLen); never write past buffer.
            if (contentEnd_ > sendBuffer_.size())
                return;
            if (lineLen > sendBuffer_.size() - contentEnd_)
                return; // drop packet; buffer full
            std::memcpy(sendBuffer_.data() + contentEnd_, buf, lineLen);
            contentEnd_ += lineLen;
            if (contentEnd_ >= kSendBatchSize)
                queueCv_.notify_one();
        }
    }

private:
    std::mutex queueMutex_;
    std::vector<char> sendBuffer_;  // fixed size, allocated once; never reallocated or shrunk
    std::size_t contentEnd_{0};     // valid data is [0, contentEnd_); never exceed sendBuffer_.size()
    std::condition_variable queueCv_;
    std::atomic<bool> runningSender_{false};
    std::thread senderThread_;

    std::mutex connectionMutex_;
    std::string host_;
    std::uint16_t port_;
    int fd_{-1};
    SSL_CTX *sslCtx_{nullptr};
    SSL *ssl_{nullptr};
    std::chrono::steady_clock::time_point sessionStart_;
    std::string identityPath_;
    std::string tlsCaPath_;
    std::string tlsServerCertPath_;
    mutable std::string lastError_;

    void senderLoop()
    {
        // NEW-N4: per-iteration try/catch so any std::system_error from condvar/mutex
        // operations or std::bad_alloc never escapes the thread (which would call
        // std::terminate). The loop continues to the next iteration.
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
                    if (!runningSender_.load())
                        break;
                    toSend = contentEnd_;
                    contentEnd_ = 0;  // reset; new data will overwrite from start (no realloc)
                }
                if (toSend == 0)
                    continue;

                // toSend <= sendBuffer_.size() <= kMaxIOBytes, so single writeExact is valid
                std::lock_guard<std::mutex> connLock(connectionMutex_);
                if (fd_ < 0)
                {
                    if (!connectUnlocked())
                        continue;
                }
                if (fd_ >= 0)
                {
                    using Sec = std::chrono::seconds::rep;
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - sessionStart_).count();
                    Sec safeElapsed = (elapsed < 0) ? 0 : elapsed;
                    if (static_cast<std::uint64_t>(safeElapsed) >= kMaxSessionSeconds)
                        closeUnlocked();
                }
                if (fd_ >= 0 && !writeExact(ssl_, fd_, sendBuffer_.data(), toSend))
                    closeUnlocked();
            }
            catch (const std::exception &e)
            {
                if (g_daemon)
                    syslog(LOG_ERR, "ntm-client: senderLoop exception: %s", e.what());
                else
                    std::cerr << "ntm-client: senderLoop exception: " << e.what() << "\n";
                // UE-7: back off after caught exception to avoid syslog flood.
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (...)
            {
                if (g_daemon)
                    syslog(LOG_ERR, "ntm-client: senderLoop caught unknown exception");
                else
                    std::cerr << "ntm-client: senderLoop caught unknown exception\n";
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void closeUnlocked()
    {
        if (ssl_)
        {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    bool connectUnlocked()
    {
        if (fd_ >= 0)
            return true;

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            lastError_ = "socket() failed";
            std::perror("socket");
            return false;
        }

        int sndbuf = 4 * 1024 * 1024;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
            std::perror("setsockopt(SO_SNDBUF)");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1)
        {
            lastError_ = "invalid server host: " + host_;
            std::cerr << "Invalid server host: " << host_ << "\n";
            ::close(fd);
            return false;
        }

        if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            lastError_ = "connect() failed (is the server reachable?)";
            std::perror("connect");
            ::close(fd);
            return false;
        }

        SSL *ssl = nullptr;
        if (sslCtx_)
        {
            ssl = SSL_new(sslCtx_);
            if (!ssl)
            {
                lastError_ = "SSL_new failed";
                std::cerr << "ntm-client: SSL_new failed\n";
                ::close(fd);
                return false;
            }
            // M8: SNI must be a DNS hostname per RFC 6066; do NOT send it for IP literals.
            // Some strict servers/middleboxes reject the handshake otherwise.
            if (!host_.empty())
            {
                unsigned char ipBuf[16];
                const bool isIp = (::inet_pton(AF_INET, host_.c_str(), ipBuf) == 1) ||
                                  (::inet_pton(AF_INET6, host_.c_str(), ipBuf) == 1);
                if (!isIp)
                    SSL_set_tlsext_host_name(ssl, host_.c_str());
            }
            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) != 1)
            {
                lastError_ = "TLS handshake failed (use --ca or --server-cert to verify server)";
                std::cerr << "ntm-client: TLS handshake failed (verify server cert with --ca or --server-cert)\n";
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                ::close(fd);
                return false;
            }
            // Post-handshake identity checks: hostname/IP verification + optional cert pinning.
            if (!verifyServerIdentityAndPin(ssl, host_, tlsServerCertPath_))
            {
                lastError_ = "server identity verification failed (host/cert mismatch)";
                std::cerr << "ntm-client: server identity verification failed (check --ca / --server-cert and host)\n";
                SSL_free(ssl);
                ::close(fd);
                return false;
            }
        }

        if (!performClientAuth(fd, ssl, identityPath_, &lastError_))
        {
            if (ssl)
            {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            return false;
        }

        // Announce all local LAN IP addresses (IPv4 and IPv6, all interfaces) so
        // that the server can attribute traffic from any of our interfaces to this
        // client's stable ID — not just the TCP connection source address.
        // One "A ip\n" line per address; non-fatal if enumeration or send fails.
        {
            // Inline LAN-check helpers (mirrors isLanIP in ntm_types.hpp).
            auto isLanV4 = [](const struct in_addr &a) -> bool {
                std::uint32_t n = ntohl(a.s_addr);
                return ((n & 0xFF000000u) == 0x7F000000u) ||  // 127.0.0.0/8
                       ((n & 0xFF000000u) == 0x0A000000u) ||  // 10.0.0.0/8
                       ((n & 0xFFF00000u) == 0xAC100000u) ||  // 172.16.0.0/12
                       ((n & 0xFFFF0000u) == 0xC0A80000u);    // 192.168.0.0/16
            };
            auto isLanV6 = [](const struct in6_addr &a) -> bool {
                static const std::uint8_t lo6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                if (std::memcmp(&a, lo6, 16) == 0) return true;       // ::1
                if ((a.s6_addr[0] & 0xFEu) == 0xFCu) return true;    // fc00::/7 ULA
                if (a.s6_addr[0] == 0xFEu &&
                    (a.s6_addr[1] & 0xC0u) == 0x80u) return true;    // fe80::/10 link-local
                return false;
            };

            struct ifaddrs *ifap = nullptr;
            if (::getifaddrs(&ifap) == 0)
            {
                char ipBuf[INET6_ADDRSTRLEN];
                std::unordered_set<std::string> seen;  // deduplicate across aliases
                bool sendOk = true;
                for (struct ifaddrs *ifa = ifap; ifa && sendOk; ifa = ifa->ifa_next)
                {
                    if (!ifa->ifa_addr) continue;
                    std::string ip;
                    if (ifa->ifa_addr->sa_family == AF_INET)
                    {
                        auto *sa4 = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
                        if (!isLanV4(sa4->sin_addr)) continue;
                        if (!::inet_ntop(AF_INET, &sa4->sin_addr, ipBuf, sizeof(ipBuf))) continue;
                        ip = ipBuf;
                    }
                    else if (ifa->ifa_addr->sa_family == AF_INET6)
                    {
                        auto *sa6 = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
                        if (!isLanV6(sa6->sin6_addr)) continue;
                        if (!::inet_ntop(AF_INET6, &sa6->sin6_addr, ipBuf, sizeof(ipBuf))) continue;
                        ip = ipBuf;
                    }
                    else continue;

                    if (!ip.empty() && seen.insert(ip).second)
                    {
                        std::string line = "A ";
                        line += ip;
                        line += '\n';
                        sendOk = writeExact(ssl, fd, line.data(), line.size());
                    }
                }
                ::freeifaddrs(ifap);
            }
        }

        fd_ = fd;
        ssl_ = ssl;
        sessionStart_ = std::chrono::steady_clock::now();
        std::cerr << "ntm-client: connected to " << host_ << ":" << port_
                  << (ssl ? " (TLS, session max 6h)" : " (plain)") << "\n";
        return true;
    }
};

class PacketSniffer
{
public:
    PacketSniffer(std::string iface, ClientConnection &connection)
        : iface_(std::move(iface)), connection_(connection)
    {
    }

    ~PacketSniffer()
    {
        stop();
    }

    void start()
    {
        if (running_.load())
            return;
        running_.store(true);
        worker_ = std::thread(&PacketSniffer::run, this);
    }

    void stop()
    {
        if (!running_.load())
            return;
        running_.store(false);
        if (pcapHandle_)
        {
            pcap_breakloop(pcapHandle_);
        }
        if (worker_.joinable())
        {
            worker_.join();
        }
    }

private:
    static void pcapCallback(u_char *user,
                             const struct pcap_pkthdr *header,
                             const u_char *packet)
    {
        auto *self = reinterpret_cast<PacketSniffer *>(user);
        self->handlePacket(header, packet);
    }

    void handlePacket(const struct pcap_pkthdr *header, const u_char *packet)
    {
        if (!running_.load())
            return;

        const u_char *l3Packet = nullptr;
        bool isIpv6 = false;

        // Handle common Linux link types: Ethernet and Linux cooked.
        switch (linkType_)
        {
        case DLT_EN10MB:
            if (header->caplen < 14)
                return;
            {
                auto etherType = static_cast<std::uint16_t>((packet[12] << 8) | packet[13]);
                if (etherType == 0x0800)
                {
                    // IPv4
                    isIpv6 = false;
                    l3Packet = packet + 14;
                }
                else if (etherType == 0x86DD)
                {
                    // IPv6
                    isIpv6 = true;
                    l3Packet = packet + 14;
                }
                else
                {
                    return;
                }
            }
            break;
        case DLT_LINUX_SLL:
        case DLT_LINUX_SLL2:
            if (header->caplen < 16)
                return;
            {
                auto proto = static_cast<std::uint16_t>((packet[14] << 8) | packet[15]);
                if (proto == 0x0800)
                {
                    // IPv4
                    isIpv6 = false;
                    l3Packet = packet + 16;
                }
                else if (proto == 0x86DD)
                {
                    // IPv6
                    isIpv6 = true;
                    l3Packet = packet + 16;
                }
                else
                {
                    return;
                }
            }
            break;
        default:
            // Unsupported link type; ignore.
            return;
        }

        if (!l3Packet)
            return;
        if (!isIpv6)
        {
            if (header->caplen <
                static_cast<bpf_u_int32>(l3Packet - packet) + sizeof(ipv4_header))
                return;
        }
        else
        {
            if (header->caplen <
                static_cast<bpf_u_int32>(l3Packet - packet) + sizeof(ipv6_header))
                return;
        }

        char srcBuf[INET6_ADDRSTRLEN];
        char dstBuf[INET6_ADDRSTRLEN];

        if (!isIpv6)
        {
            auto *ip4 = reinterpret_cast<const ipv4_header *>(l3Packet);
            if (!inet_ntop(AF_INET, &ip4->src_addr, srcBuf, sizeof(srcBuf)))
                return;
            if (!inet_ntop(AF_INET, &ip4->dst_addr, dstBuf, sizeof(dstBuf)))
                return;
        }
        else
        {
            auto *ip6 = reinterpret_cast<const ipv6_header *>(l3Packet);
            if (!inet_ntop(AF_INET6, ip6->src_addr, srcBuf, sizeof(srcBuf)))
                return;
            if (!inet_ntop(AF_INET6, ip6->dst_addr, dstBuf, sizeof(dstBuf)))
                return;
        }

        PacketMeta meta;
        meta.iface = iface_;
        meta.srcIp = srcBuf;
        meta.dstIp = dstBuf;
        meta.bytes = header->len;

        connection_.sendPacket(meta);
    }

    void run()
    {
        // NEW-N4: defensive try/catch so any std::exception inside the pcap loop
        // never escapes the std::thread (which would call std::terminate). The
        // pcap callback path is mostly C / fixed-size I/O, but sendPacket holds a
        // mutex and uses std::memcpy on a fixed buffer; any future change should
        // remain safe under this guard.
        try
        {
        char errbuf[PCAP_ERRBUF_SIZE];
        std::memset(errbuf, 0, sizeof(errbuf));

        // Use pcap_create/activate so we can tune buffer and snaplen for
        // high-throughput links.
        pcapHandle_ = pcap_create(iface_.c_str(), errbuf);
        if (!pcapHandle_)
        {
            std::cerr << "ntm-client: pcap_create failed for " << iface_
                      << ": " << errbuf << "\n";
            return;
        }

        // Capture only the first N bytes; enough for IP headers but keeps
        // per-packet cost down.
        if (pcap_set_snaplen(pcapHandle_, 192) != 0)
        {
            std::cerr << "ntm-client: pcap_set_snaplen failed for " << iface_ << "\n";
        }

        // Promiscuous to see all traffic on the interface.
        if (pcap_set_promisc(pcapHandle_, 1) != 0)
        {
            std::cerr << "ntm-client: pcap_set_promisc failed for " << iface_ << "\n";
        }

        // Millisecond timeout for batching.
        if (pcap_set_timeout(pcapHandle_, 10) != 0)
        {
            std::cerr << "ntm-client: pcap_set_timeout failed for " << iface_ << "\n";
        }

        // Larger buffer to better tolerate bursts.
        if (pcap_set_buffer_size(pcapHandle_, 16 * 1024 * 1024) != 0)
        {
            std::cerr << "ntm-client: pcap_set_buffer_size failed for " << iface_ << "\n";
        }

#ifdef PCAP_TSTAMP_ADAPTER_UNSYNCED
        // Best-effort immediate mode when available; reduces latency.
        if (pcap_set_immediate_mode(pcapHandle_, 1) != 0)
        {
            // Not fatal.
        }
#endif

        int activateStatus = pcap_activate(pcapHandle_);
        if (activateStatus < 0)
        {
            std::cerr << "ntm-client: pcap_activate failed for " << iface_
                      << ": " << pcap_geterr(pcapHandle_) << "\n";
            pcap_close(pcapHandle_);
            pcapHandle_ = nullptr;
            return;
        }

        linkType_ = pcap_datalink(pcapHandle_);

        // Filter IPv4 and IPv6 packets to reduce load.
        struct bpf_program fp;
        if (pcap_compile(pcapHandle_, &fp, "ip or ip6", 1, PCAP_NETMASK_UNKNOWN) == 0)
        {
            if (pcap_setfilter(pcapHandle_, &fp) != 0)
            {
                std::cerr << "ntm-client: failed to set filter on " << iface_ << "\n";
            }
            pcap_freecode(&fp);
        }

        while (running_.load())
        {
            int ret = pcap_dispatch(pcapHandle_, 16, &PacketSniffer::pcapCallback,
                                    reinterpret_cast<u_char *>(this));
            if (ret == -1)
            {
                break; // error
            }
            // ret == 0 means timeout; loop again.
        }

        pcap_close(pcapHandle_);
        pcapHandle_ = nullptr;
        } // end of try (NEW-N4)
        catch (const std::exception &e)
        {
            if (g_daemon)
                syslog(LOG_ERR, "ntm-client: PacketSniffer thread exception: %s", e.what());
            else
                std::cerr << "ntm-client: PacketSniffer thread exception: " << e.what() << "\n";
            if (pcapHandle_)
            {
                pcap_close(pcapHandle_);
                pcapHandle_ = nullptr;
            }
        }
        catch (...)
        {
            if (g_daemon)
                syslog(LOG_ERR, "ntm-client: PacketSniffer thread caught unknown exception");
            else
                std::cerr << "ntm-client: PacketSniffer thread caught unknown exception\n";
            if (pcapHandle_)
            {
                pcap_close(pcapHandle_);
                pcapHandle_ = nullptr;
            }
        }
    }

    std::string iface_;
    ClientConnection &connection_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    pcap_t *pcapHandle_{nullptr};
    int linkType_{DLT_EN10MB};
};

static std::atomic<bool> g_running{true};

void handleSignal(int)
{
    g_running.store(false);
}

void daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        std::exit(EXIT_SUCCESS);
    }

    if (setsid() < 0)
    {
        std::perror("setsid");
        std::exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0)
    {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        std::exit(EXIT_SUCCESS);
    }

    umask(0);
    // NEW-N6: report (but don't fatally fail on) chdir/dup2 errors. By the time we
    // reach here in the client we may already have openlog() set up (client_main
    // does openlog before runClient when --daemon is set), so prefer syslog.
    auto warn = [](const char *what) {
        if (g_daemon)
            syslog(LOG_WARNING, "ntm-client: %s failed: %s", what, std::strerror(errno));
        else
            std::cerr << "ntm-client: " << what << " failed: " << std::strerror(errno) << "\n";
    };
    if (chdir("/") != 0)
        warn("chdir(\"/\")");

    int fd = ::open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        if (dup2(fd, STDIN_FILENO) < 0)  warn("dup2(stdin)");
        if (dup2(fd, STDOUT_FILENO) < 0) warn("dup2(stdout)");
        if (dup2(fd, STDERR_FILENO) < 0) warn("dup2(stderr)");
        if (fd > 2)
            close(fd);
    }
    else
    {
        warn("open(/dev/null)");
    }
}

int runClient(const std::string &serverHost,
              std::uint16_t serverPort,
              bool daemonMode,
              const std::string &identityPath,
              const std::string &tlsCaPath,
              const std::string &tlsServerCertPath,
              std::size_t sendBufferBytes,
              bool verbose)
{
    g_verbose = verbose;
    g_daemon = daemonMode;
    if (daemonMode)
    {
        daemonize();
    }

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    const char *id = identityPath.empty() ? "(none)" : identityPath.c_str();
    const char *ca = tlsCaPath.empty() ? "(none)" : tlsCaPath.c_str();
    const char *sc = tlsServerCertPath.empty() ? "(none)" : tlsServerCertPath.c_str();
    if (daemonMode)
    {
        syslog(LOG_INFO, "connecting to %s:%u (identity=%s, ca=%s, server-cert=%s)",
               serverHost.c_str(), static_cast<unsigned>(serverPort), id, ca, sc);
    }
    else
    {
        std::cerr << "ntm-client: connecting to " << serverHost << ":" << serverPort
                  << " (identity=" << id << ", ca=" << ca << ", server-cert=" << sc << ")\n";
    }

    ClientConnection connection(serverHost, serverPort, identityPath, tlsCaPath, tlsServerCertPath, sendBufferBytes);
    if (!connection.connectOnce())
    {
        const std::string &err = connection.lastError();
        if (daemonMode)
            syslog(LOG_ERR, "failed to connect to server: %s", err.empty() ? "unknown" : err.c_str());
        else
            std::cerr << "ntm-client: failed to connect to server" << (err.empty() ? "" : ": " + err) << "\n";
        return 1;
    }

    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    if (pcap_findalldevs(&alldevs, errbuf) != 0 || !alldevs)
    {
        if (daemonMode)
            syslog(LOG_ERR, "pcap_findalldevs failed: %s (no interfaces or permission denied?)", errbuf[0] ? errbuf : "no devices");
        else
            std::cerr << "ntm-client: pcap_findalldevs failed: " << (errbuf[0] ? errbuf : "no devices") << "\n";
        return 1;
    }

    std::vector<std::unique_ptr<PacketSniffer>> sniffers;

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next)
    {
        if (!d->name)
            continue;
        if (!d->addresses)
            continue;

        std::string name(d->name);
        auto sniffer = std::make_unique<PacketSniffer>(name, connection);
        sniffer->start();
        sniffers.push_back(std::move(sniffer));
    }

    pcap_freealldevs(alldevs);

    while (g_running.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    for (auto &sniffer : sniffers)
    {
        if (sniffer)
        {
            sniffer->stop();
        }
    }

    connection.close();
    return 0;
}

} // namespace ntm

