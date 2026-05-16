#include "proto_client_server.hpp"
#include "proto_server_monitor.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

namespace
{
inline constexpr std::size_t kMaxIOBytes = 2 * 1024 * 1024;

static bool readExact(SSL *ssl, int fd, void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes)
        return false;
    std::uint8_t *p = static_cast<std::uint8_t *>(buf);
    while (n > 0)
    {
        int r = ssl ? SSL_read(ssl, p, static_cast<int>(n)) : static_cast<int>(::recv(fd, p, n, 0));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

static bool writeExact(SSL *ssl, int fd, const void *buf, std::size_t n)
{
    if (n == 0 || n > kMaxIOBytes)
        return false;
    const std::uint8_t *p = static_cast<const std::uint8_t *>(buf);
    while (n > 0)
    {
        int r = ssl ? SSL_write(ssl, p, static_cast<int>(n)) : static_cast<int>(::send(fd, p, n, MSG_NOSIGNAL));
        if (r <= 0)
            return false;
        p += static_cast<std::size_t>(r);
        n -= static_cast<std::size_t>(r);
    }
    return true;
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
        return false;

    bool ok = true;
    if (!host.empty())
    {
        unsigned char buf[16];
        if (::inet_pton(AF_INET, host.c_str(), buf) == 1 || ::inet_pton(AF_INET6, host.c_str(), buf) == 1)
            ok = (X509_check_ip_asc(peer, host.c_str(), 0) == 1);
        else
            ok = (X509_check_host(peer, host.c_str(), 0, 0, nullptr) == 1);
    }

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
        }
    }

    X509_free(peer);
    return ok;
}

static SSL_CTX *createClientTLSContext(const std::string &caPath)
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        return nullptr;
    // M2: when no CA is provided (pin-only mode), use VERIFY_NONE so the handshake
    // does not fail for lack of a chain. The post-handshake fingerprint check
    // (verifyServerIdentityAndPin) is what actually authenticates the server.
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

// M6: warn (not fatal) if the private identity key file is group/world-readable
// or owned by another user.
static void checkIdentityFilePermissions(const std::string &path)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0)
        return;
    const mode_t openBits = st.st_mode & (S_IRWXG | S_IRWXO);
    if ((openBits & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH | S_IXGRP | S_IXOTH)) != 0)
    {
        std::cerr << "ntm-monitor: WARNING: identity key has group/world permissions; "
                  << "tighten with 'chmod 600' (path=" << path
                  << " mode=" << std::oct << (st.st_mode & 07777) << std::dec << ")\n";
    }
    if (st.st_uid != ::geteuid())
    {
        std::cerr << "ntm-monitor: WARNING: identity key is not owned by current user (path="
                  << path << ")\n";
    }
}

static bool performMonitorAuthV2(int fd, SSL *ssl, const std::string &identityPath)
{
    if (identityPath.empty())
        return true;

    checkIdentityFilePermissions(identityPath);

    FILE *fp = std::fopen(identityPath.c_str(), "r");
    if (!fp)
    {
        std::cerr << "ntm-monitor: cannot open identity file: " << identityPath << "\n";
        return false;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    if (!pkey || EVP_PKEY_id(pkey) != EVP_PKEY_ED25519)
    {
        std::cerr << "ntm-monitor: identity key must be Ed25519\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::size_t pubLen = ntm::kAuthPubkeyLen;
    std::uint8_t pubkey[ntm::kAuthPubkeyLen];
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubLen) != 1 || pubLen != ntm::kAuthPubkeyLen)
    {
        std::cerr << "ntm-monitor: failed to get public key\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::uint8_t version = static_cast<std::uint8_t>(ntm::kAuthVersionV2);
    if (!writeExact(ssl, fd, &version, 1))
    {
        std::cerr << "ntm-monitor: failed to send auth version\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::uint8_t nonce[ntm::kAuthNonceLen];
    if (!readExact(ssl, fd, nonce, sizeof(nonce)))
    {
        std::cerr << "ntm-monitor: failed to read auth nonce\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    std::string toSign(reinterpret_cast<const char *>(ntm::kAuthSignPrefixV2), ntm::kAuthSignPrefixV2Len);
    toSign.append(reinterpret_cast<const char *>(nonce), sizeof(nonce));

    std::size_t sigLen = ntm::kAuthSignatureLen;
    std::uint8_t sig[ntm::kAuthSignatureLen];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
              && EVP_DigestSign(ctx, sig, &sigLen,
                                reinterpret_cast<const unsigned char *>(toSign.data()), toSign.size()) == 1
              && sigLen == ntm::kAuthSignatureLen;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok)
    {
        std::cerr << "ntm-monitor: Ed25519 sign failed\n";
        return false;
    }

    std::uint8_t msg[ntm::kAuthPubkeyLen + ntm::kAuthSignatureLen];
    std::memcpy(msg, pubkey, ntm::kAuthPubkeyLen);
    std::memcpy(msg + ntm::kAuthPubkeyLen, sig, ntm::kAuthSignatureLen);

    if (!writeExact(ssl, fd, msg, sizeof(msg)))
    {
        std::cerr << "ntm-monitor: failed to send auth message\n";
        return false;
    }

    std::uint8_t result = 0xff;
    if (!readExact(ssl, fd, &result, 1) || result != 0x00)
    {
        std::cerr << "ntm-monitor: server rejected authentication\n";
        return false;
    }

    return true;
}
} // namespace

// H3: parse a TCP port from a CLI string; print error and return false on bad input.
static bool parsePortArg(const char *flag, const char *valStr, std::uint16_t &out)
{
    try
    {
        std::size_t consumed = 0;
        long n = std::stol(valStr, &consumed);
        if (consumed != std::strlen(valStr) || n < 1 || n > 65535)
            throw std::out_of_range("port out of range");
        out = static_cast<std::uint16_t>(n);
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "ntm-monitor: invalid value for " << flag << ": '" << valStr
                  << "' (expected 1-65535): " << e.what() << "\n";
        return false;
    }
}

// L4: ntm-monitor config struct + key=value file loader (mirrors ntm-client style).
struct MonitorConfig
{
    std::string server;            // host
    std::uint16_t port{ntm::kDefaultMonitorPort};
    std::string identity;
    std::string ca;
    std::string server_cert;
    bool tls{false};
    bool verbose{false};
};

// Returns true on successful read; false only when the file could not be opened.
// Unknown keys are reported on stderr (no fail-open via typo).
static bool loadMonitorConfig(const std::string &path, MonitorConfig &out, std::size_t *recognizedOut = nullptr)
{
    if (recognizedOut) *recognizedOut = 0;
    std::ifstream f(path);
    if (!f) return false;
    static const std::set<std::string> known = {
        "server", "monitor_port", "identity", "ca", "server_cert", "tls", "verbose",
    };
    std::string line;
    std::size_t lineNo = 0;
    std::size_t recognized = 0;
    auto isTrue = [](const std::string &s) {
        std::string v = s;
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v == "1" || v == "true" || v == "yes";
    };
    while (std::getline(f, line))
    {
        ++lineNo;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') continue;
        std::size_t eq = line.find('=', start);
        if (eq == std::string::npos) continue;
        std::string key = line.substr(start, eq - start);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        std::string val = line.substr(eq + 1);
        std::size_t vs = val.find_first_not_of(" \t");
        if (vs != std::string::npos) val = val.substr(vs);

        if (known.find(key) == known.end())
        {
            std::cerr << "ntm-monitor: " << path << " line " << lineNo
                      << ": unknown config key '" << key << "' (ignored)\n";
            continue;
        }
        ++recognized;
        if      (key == "server")      out.server = val;
        else if (key == "monitor_port")
        {
            std::uint16_t p = 0;
            if (parsePortArg("monitor_port", val.c_str(), p)) out.port = p;
        }
        else if (key == "identity")    out.identity = val;
        else if (key == "ca")          { out.ca = val; out.tls = true; }
        else if (key == "server_cert") { out.server_cert = val; out.tls = true; }
        else if (key == "tls")         out.tls = isTrue(val);
        else if (key == "verbose")     out.verbose = isTrue(val);
    }
    if (recognizedOut) *recognizedOut = recognized;
    return true;
}

int main(int argc, char *argv[])
{
    // L4: pre-scan for --config so file values seed the defaults; CLI then overrides.
    MonitorConfig fileCfg;
    std::string configPath;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) { configPath = argv[++i]; break; }
        if (a == "--help" || a == "-h")
        {
            std::cout <<
                "Usage: ntm-monitor [--config FILE] [--server HOST] [--monitor-port N] "
                "[--tls] [--ca CA_FILE] [--server-cert SERVER_PEM] [--identity PEM] [--verbose]\n";
            return 0;
        }
    }
    if (!configPath.empty())
    {
        std::size_t recognized = 0;
        if (!loadMonitorConfig(configPath, fileCfg, &recognized))
        {
            std::cerr << "ntm-monitor: cannot open --config file: '" << configPath
                      << "' (refusing to fall back to defaults)\n";
            return 1;
        }
        if (recognized == 0)
        {
            std::cerr << "ntm-monitor: WARNING: --config file '" << configPath
                      << "' contained no recognized keys\n";
        }
    }

    std::string host = fileCfg.server.empty() ? std::string("127.0.0.1") : fileCfg.server;
    std::uint16_t port = fileCfg.port;
    std::string identityPath = fileCfg.identity;
    std::string caPath = fileCfg.ca;
    std::string pinnedServerCertPath = fileCfg.server_cert;
    bool useTls = fileCfg.tls;
    bool verbose = fileCfg.verbose;

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) { ++i; continue; }
        if ((a == "--help" || a == "-h"))
            return 0;  // already shown above
        else if (a == "--server" && i + 1 < argc)
            host = argv[++i];
        else if (a == "--monitor-port" && i + 1 < argc)
        {
            if (!parsePortArg("--monitor-port", argv[++i], port))
                return 1;
        }
        else if (a == "--identity" && i + 1 < argc)
            identityPath = argv[++i];
        else if (a == "--ca" && i + 1 < argc)
        {
            caPath = argv[++i];
            useTls = true;
        }
        else if (a == "--server-cert" && i + 1 < argc)
        {
            pinnedServerCertPath = argv[++i];
            useTls = true;
        }
        else if (a == "--tls")
            useTls = true;
        else if (a == "--verbose")
            verbose = true;
        else
        {
            std::cerr << "ntm-monitor: unknown or incomplete argument: '" << a << "'\n";
            return 1;
        }
    }
    if (verbose)
    {
        std::cerr << "ntm-monitor: effective settings: server=" << host
                  << " port=" << port
                  << " tls=" << (useTls ? "yes" : "no")
                  << " identity=" << (identityPath.empty() ? "(none)" : identityPath)
                  << " ca=" << (caPath.empty() ? "(none)" : caPath)
                  << " server-cert=" << (pinnedServerCertPath.empty() ? "(none)" : pinnedServerCertPath)
                  << "\n";
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        std::perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        std::cerr << "ntm-monitor: invalid server host: " << host << "\n";
        ::close(fd);
        return 1;
    }

    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::perror("connect");
        ::close(fd);
        return 1;
    }

    SSL_CTX *sslCtx = nullptr;
    SSL *ssl = nullptr;
    if (useTls)
    {
        sslCtx = createClientTLSContext(caPath);
        if (!sslCtx)
        {
            std::cerr << "ntm-monitor: failed to create TLS context\n";
            ERR_print_errors_fp(stderr);
            ::close(fd);
            return 1;
        }
        ssl = SSL_new(sslCtx);
        if (!ssl)
        {
            std::cerr << "ntm-monitor: SSL_new failed\n";
            SSL_CTX_free(sslCtx);
            ::close(fd);
            return 1;
        }
        if (!host.empty())
        {
            // M8: only send SNI for DNS hostnames; IP literals violate RFC 6066.
            unsigned char ipBuf[16];
            const bool isIp = (::inet_pton(AF_INET, host.c_str(), ipBuf) == 1) ||
                              (::inet_pton(AF_INET6, host.c_str(), ipBuf) == 1);
            if (!isIp)
                SSL_set_tlsext_host_name(ssl, host.c_str());
        }
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1)
        {
            std::cerr << "ntm-monitor: TLS handshake failed\n";
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(sslCtx);
            ::close(fd);
            return 1;
        }
        if (!verifyServerIdentityAndPin(ssl, host, pinnedServerCertPath))
        {
            std::cerr << "ntm-monitor: server identity verification failed\n";
            SSL_free(ssl);
            SSL_CTX_free(sslCtx);
            ::close(fd);
            return 1;
        }
    }

    if (!performMonitorAuthV2(fd, ssl, identityPath))
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sslCtx)
            SSL_CTX_free(sslCtx);
        ::close(fd);
        return 1;
    }

    const std::string cmd = std::string(ntm::kMonitorCmdIfaceSummary) + "\n";
    if (!writeExact(ssl, fd, cmd.data(), cmd.size()))
    {
        std::cerr << "ntm-monitor: failed to send command\n";
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sslCtx)
            SSL_CTX_free(sslCtx);
        ::close(fd);
        return 1;
    }

    // L1: line-based response parsing. We read until we see a line whose contents
    // are exactly the END token (or until the cap is hit). This avoids being
    // fooled by an entity name that happens to contain the substring "END\n".
    std::string out;
    out.reserve(4096);
    char buf[4096];
    constexpr std::size_t kMaxResponseBytes = 8 * 1024 * 1024;
    bool sawEndLine = false;
    std::size_t scannedTo = 0;  // amortise the line-scan cost
    const std::string endTok = ntm::kMonitorTokEnd;
    while (out.size() < kMaxResponseBytes)
    {
        int n = ssl ? SSL_read(ssl, buf, sizeof(buf)) : static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
        if (n <= 0)
            break;
        out.append(buf, buf + n);
        // Walk the new bytes one line at a time looking for the END line.
        while (scannedTo < out.size())
        {
            std::size_t nl = out.find('\n', scannedTo);
            if (nl == std::string::npos) break;
            std::size_t lineStart = scannedTo;
            std::size_t lineLen = nl - lineStart;
            if (lineLen == endTok.size() &&
                out.compare(lineStart, endTok.size(), endTok) == 0)
            {
                sawEndLine = true;
            }
            scannedTo = nl + 1;
            if (sawEndLine) break;
        }
        if (sawEndLine) break;
    }
    if (!sawEndLine && out.size() >= kMaxResponseBytes)
    {
        std::cerr << "ntm-monitor: response exceeded " << kMaxResponseBytes
                  << " bytes without END marker; truncating\n";
    }

    std::cout << out;

    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sslCtx)
        SSL_CTX_free(sslCtx);
    ::close(fd);
    return 0;
}

