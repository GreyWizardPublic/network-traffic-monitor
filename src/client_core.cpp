#include "client_core.hpp"
#include "client_platform.hpp"
#include "client.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

namespace ntm
{

// ---------------------------------------------------------------------------
// LAN address classification
// ---------------------------------------------------------------------------

bool isLanAddrV4(std::uint32_t networkOrderAddr)
{
    std::uint32_t n = ntohl(networkOrderAddr);
    return ((n & 0xFF000000u) == 0x7F000000u) ||  // 127.0.0.0/8
           ((n & 0xFF000000u) == 0x0A000000u) ||  // 10.0.0.0/8
           ((n & 0xFFF00000u) == 0xAC100000u) ||  // 172.16.0.0/12
           ((n & 0xFFFF0000u) == 0xC0A80000u);    // 192.168.0.0/16
}

bool isLanAddrV6(const std::uint8_t addr[16])
{
    static const std::uint8_t lo6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (std::memcmp(addr, lo6, 16) == 0) return true;       // ::1
    if ((addr[0] & 0xFEu) == 0xFCu)      return true;       // fc00::/7 ULA
    if (addr[0] == 0xFEu && (addr[1] & 0xC0u) == 0x80u) return true; // fe80::/10
    return false;
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

SSL_CTX *createClientTLSContext(const std::string &caPath,
                                const std::string &serverCertPath)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;

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
    (void)serverCertPath; // used at verify time, not context creation
    return ctx;
}

X509 *loadPemCert(const std::string &path)
{
    if (path.empty()) return nullptr;
    FILE *fp = std::fopen(path.c_str(), "r");
    if (!fp) return nullptr;
    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    return cert;
}

bool sha256Fingerprint(const X509 *cert, unsigned char out[32])
{
    unsigned int n = 0;
    return cert && X509_digest(cert, EVP_sha256(), out, &n) == 1 && n == 32;
}

bool verifyServerIdentityAndPin(SSL *ssl, const std::string &host,
                                const std::string &pinnedServerCertPath,
                                bool verbose, bool isDaemon)
{
    if (!ssl) return false;

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer)
    {
        if (verbose)
            platform::ntmLog(platform::LogLevel::Err, isDaemon,
                             "ntm-client: no peer certificate presented by server");
        return false;
    }

    bool ok = true;

    if (!host.empty())
    {
        unsigned char buf[16];
        if (::inet_pton(AF_INET,  host.c_str(), buf) == 1 ||
            ::inet_pton(AF_INET6, host.c_str(), buf) == 1)
            ok = (X509_check_ip_asc(peer, host.c_str(), 0) == 1);
        else
            ok = (X509_check_host(peer, host.c_str(), 0, 0, nullptr) == 1);

        if (verbose && !ok)
            platform::ntmLog(platform::LogLevel::Err, isDaemon,
                             "ntm-client: server certificate hostname/IP check failed for host=" + host);
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
            ok = sha256Fingerprint(peer, a) && sha256Fingerprint(pinned, b) &&
                 std::memcmp(a, b, 32) == 0;
            X509_free(pinned);
            if (verbose && !ok)
                platform::ntmLog(platform::LogLevel::Err, isDaemon,
                                 "ntm-client: server certificate fingerprint mismatch (pinning failed)");
        }
    }

    X509_free(peer);
    return ok;
}

// ---------------------------------------------------------------------------
// Ed25519 client authentication
// ---------------------------------------------------------------------------

bool performClientAuth(void *sslVoid, std::uintptr_t rawFd,
                       const std::string &identityPath,
                       bool isDaemon, bool verbose,
                       std::string *errOut)
{
    auto setErr = [&](const char *msg) { if (errOut) *errOut = msg; };
    if (identityPath.empty()) return true;

    SSL *ssl = static_cast<SSL *>(sslVoid);
    platform::SockFd fd = static_cast<platform::SockFd>(rawFd);

    platform::checkIdentityFilePermissions(identityPath, isDaemon, verbose);

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
        EVP_PKEY_free(pkey);
        return false;
    }

    std::uint8_t version = static_cast<std::uint8_t>(kAuthVersionV2);
    if (!platform::writeExact(ssl, fd, &version, 1))
    {
        setErr("failed to send auth version");
        EVP_PKEY_free(pkey);
        return false;
    }

    std::uint8_t nonce[kAuthNonceLen];
    if (!platform::readExact(ssl, fd, nonce, sizeof(nonce)))
    {
        setErr("failed to read auth nonce");
        EVP_PKEY_free(pkey);
        return false;
    }

    std::string toSign(reinterpret_cast<const char *>(kAuthSignPrefixV2), kAuthSignPrefixV2Len);
    toSign.append(reinterpret_cast<const char *>(nonce), sizeof(nonce));

    std::size_t sigLen = kAuthSignatureLen;
    std::uint8_t sig[kAuthSignatureLen];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx
        && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
        && EVP_DigestSign(ctx, sig, &sigLen,
                          reinterpret_cast<const unsigned char *>(toSign.data()),
                          toSign.size()) == 1
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

    if (!platform::writeExact(ssl, fd, msg, sizeof(msg)))
    {
        setErr("failed to send auth message");
        return false;
    }

    std::uint8_t result = 0xff;
    if (!platform::readExact(ssl, fd, &result, 1) || result != 0x00)
    {
        setErr("server rejected authentication (key not in server allowed list?)");
        std::cerr << "ntm-client: server rejected authentication\n";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

static bool parseConfigLine(const std::string &key, const std::string &val,
                            ClientConfig &out)
{
    std::string v = val.size() <= kMaxConfigValueLen ? val : val.substr(0, kMaxConfigValueLen);
    if (key == "server")       { out.server = v; return true; }
    if (key == "port")
    {
        try {
            unsigned long p = std::stoul(v);
            if (p != 0 && p <= 65535) out.port = static_cast<std::uint16_t>(p);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "identity")     { out.identityPath = v; return true; }
    if (key == "ca")           { out.tlsCaPath = v; return true; }
    if (key == "server_cert")  { out.tlsServerCertPath = v; return true; }
    if (key == "send_buffer_bytes")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n < kSendBufferMinBytes) n = kSendBufferMinBytes;
            if (n > kMaxIOBytes)         n = kMaxIOBytes;
            out.sendBufferBytes = static_cast<std::size_t>(n);
        } catch (const std::exception &) {}
        return true;
    }
    if (key == "verbose")
    {
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        out.verbose = (lower == "1" || lower == "true" || lower == "yes");
        return true;
    }
    if (key == "external_ip_url")
    {
        if (!v.empty()) out.externalIpUrl = v;
        return true;
    }
    if (key == "external_ip_timeout_ms")
    {
        try {
            unsigned long n = std::stoul(v);
            if (n >= 500 && n <= 30000)
                out.externalIpTimeoutMs = static_cast<unsigned>(n);
        } catch (const std::exception &) {}
        return true;
    }
    return false;
}

bool loadClientConfig(const std::string &configPath, ClientConfig &out)
{
    std::ifstream f(configPath);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.size() > kMaxConfigLineLen)
            line.resize(kMaxConfigLineLen);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') continue;
        std::size_t eq = line.find('=', start);
        if (eq == std::string::npos) continue;
        std::string key = line.substr(start, eq - start);
        std::size_t keyEnd = key.find_last_not_of(" \t");
        if (keyEnd != std::string::npos && keyEnd < key.size())
            key.resize(keyEnd + 1);
        std::string val = line.substr(eq + 1);
        std::size_t valStart = val.find_first_not_of(" \t");
        if (valStart != std::string::npos) val = val.substr(valStart);
        parseConfigLine(key, val, out);
    }
    return true;
}

} // namespace ntm
