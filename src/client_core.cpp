#include "client_core.hpp"
#include "client_platform.hpp"
#include "client.hpp"
#include "client_config_parse.hpp"  // parseConfigLine + loadClientConfig (inline)

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
#  include <wincrypt.h>   // CertOpenSystemStoreW, CertEnumCertificatesInStore
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
#include <sstream>
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

#ifdef _WIN32
// HARMONIZE-LINUX: Windows loads trust anchors from the OS Certificate Store;
// Linux uses SSL_CTX_set_default_verify_paths() (file-based system CA bundle).
// Both paths are triggered by ca=system in the config.
static void loadWindowsCertStore(SSL_CTX *ctx)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    for (const wchar_t *name : {L"ROOT", L"CA"})
    {
        HCERTSTORE hStore = CertOpenSystemStoreW(0, name);
        if (!hStore) continue;
        PCCERT_CONTEXT pCert = nullptr;
        while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr)
        {
            const unsigned char *p = pCert->pbCertEncoded;
            X509 *x509 = d2i_X509(nullptr, &p,
                                   static_cast<long>(pCert->cbCertEncoded));
            if (x509)
            {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
        }
        CertCloseStore(hStore, 0);
    }
}
#endif

SSL_CTX *createClientTLSContext(const std::string &caPath,
                                const std::string &serverCertPath)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;

    const bool useSystem = (caPath == "system");
    const bool useCaFile = !caPath.empty() && !useSystem;

    SSL_CTX_set_verify(ctx,
        (useCaFile || useSystem) ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
        nullptr);

    if (useCaFile)
    {
        if (SSL_CTX_load_verify_locations(ctx, caPath.c_str(), nullptr) != 1)
        {
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    else if (useSystem)
    {
#ifdef _WIN32
        loadWindowsCertStore(ctx);
#else
        SSL_CTX_set_default_verify_paths(ctx);
#endif
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // ALPN: advertise "ntm-wire" so the server can route this connection as a
    // data-ingestion channel when the dashboard and client share a single port.
    // Browsers send "http/1.1" by default; the server selects "ntm-wire" first.
    // Wire format: 1-byte length prefix followed by the ASCII protocol name.
    static const unsigned char kAlpn[] = "\x08ntm-wire";
    SSL_CTX_set_alpn_protos(ctx, kAlpn, sizeof(kAlpn) - 1);

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

// Format a 32-byte buffer as lowercase hex (64 chars + NUL).
static std::string hexDump32(const unsigned char b[32])
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i)
    {
        out.push_back(kHex[(b[i] >> 4) & 0xf]);
        out.push_back(kHex[b[i] & 0xf]);
    }
    return out;
}

bool verifyServerIdentityAndPin(SSL *ssl, const std::string &host,
                                const std::string &pinnedServerCertPath,
                                bool verbose, bool isDaemon)
{
    if (!ssl) return false;

    // ── ALPN ────────────────────────────────────────────────────────────────
    // Log the ALPN the server actually selected. If this is "http/1.1" instead
    // of "ntm-wire", the connection went through an HTTP proxy (e.g. Cloudflare)
    // that does not forward the ntm-wire protocol — the auth handshake will fail.
    if (verbose)
    {
        const unsigned char *alpnData = nullptr;
        unsigned int alpnLen = 0;
        SSL_get0_alpn_selected(ssl, &alpnData, &alpnLen);
        std::string alpn = alpnLen ? std::string(reinterpret_cast<const char *>(alpnData), alpnLen)
                                   : "(none negotiated)";
        const bool alpnOk = (alpn == "ntm-wire");
        platform::ntmLog(alpnOk ? platform::LogLevel::Info : platform::LogLevel::Warn,
                         isDaemon,
                         "ntm-client: [tls] ALPN negotiated: '" + alpn + "'"
                         + (alpnOk ? "" : " — expected 'ntm-wire'; connection may be going through an HTTP proxy"));
    }

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer)
    {
        platform::ntmLog(platform::LogLevel::Err, isDaemon,
                         "ntm-client: [tls] server presented no certificate");
        return false;
    }

    // ── Cert subject & fingerprint ───────────────────────────────────────────
    if (verbose)
    {
        char subj[256] = {};
        X509_NAME_oneline(X509_get_subject_name(peer), subj, sizeof(subj));
        platform::ntmLog(platform::LogLevel::Info, isDaemon,
                         std::string("ntm-client: [tls] server cert subject: ") + subj);

        unsigned char fp[32]{};
        if (sha256Fingerprint(peer, fp))
            platform::ntmLog(platform::LogLevel::Info, isDaemon,
                             "ntm-client: [tls] server cert SHA-256: " + hexDump32(fp));
    }

    bool ok = true;

    // ── Hostname / IP check ──────────────────────────────────────────────────
    if (!host.empty())
    {
        unsigned char buf[16];
        if (::inet_pton(AF_INET,  host.c_str(), buf) == 1 ||
            ::inet_pton(AF_INET6, host.c_str(), buf) == 1)
            ok = (X509_check_ip_asc(peer, host.c_str(), 0) == 1);
        else
            ok = (X509_check_host(peer, host.c_str(), 0, 0, nullptr) == 1);

        if (verbose)
            platform::ntmLog(ok ? platform::LogLevel::Info : platform::LogLevel::Err, isDaemon,
                             "ntm-client: [tls] hostname check for '" + host + "': "
                             + (ok ? "passed" : "FAILED"));
        else if (!ok)
            platform::ntmLog(platform::LogLevel::Err, isDaemon,
                             "ntm-client: server certificate hostname check failed for host=" + host);
    }

    // ── Certificate pinning ──────────────────────────────────────────────────
    if (ok && !pinnedServerCertPath.empty())
    {
        if (verbose)
            platform::ntmLog(platform::LogLevel::Info, isDaemon,
                             "ntm-client: [tls] checking cert pin against: " + pinnedServerCertPath);
        X509 *pinned = loadPemCert(pinnedServerCertPath);
        if (!pinned)
        {
            platform::ntmLog(platform::LogLevel::Err, isDaemon,
                             "ntm-client: [tls] cannot load pinned cert from: " + pinnedServerCertPath);
            ok = false;
        }
        else
        {
            unsigned char a[32]{}, b[32]{};
            const bool fpMatch = sha256Fingerprint(peer, a) && sha256Fingerprint(pinned, b) &&
                                 std::memcmp(a, b, 32) == 0;
            X509_free(pinned);
            if (verbose && !fpMatch)
            {
                platform::ntmLog(platform::LogLevel::Err, isDaemon,
                                 "ntm-client: [tls] cert pin mismatch");
                platform::ntmLog(platform::LogLevel::Err, isDaemon,
                                 "ntm-client: [tls]   server cert  SHA-256: " + hexDump32(a));
                platform::ntmLog(platform::LogLevel::Err, isDaemon,
                                 "ntm-client: [tls]   pinned cert  SHA-256: " + hexDump32(b));
            }
            else if (!fpMatch)
                platform::ntmLog(platform::LogLevel::Err, isDaemon,
                                 "ntm-client: server certificate fingerprint mismatch (pinning failed)");
            ok = fpMatch;
        }
    }
    else if (verbose && pinnedServerCertPath.empty())
    {
        platform::ntmLog(platform::LogLevel::Info, isDaemon,
                         "ntm-client: [tls] cert pinning: disabled (no --server-cert)");
    }

    X509_free(peer);
    if (verbose)
        platform::ntmLog(ok ? platform::LogLevel::Info : platform::LogLevel::Err, isDaemon,
                         std::string("ntm-client: [tls] identity verification: ") + (ok ? "passed" : "FAILED"));
    return ok;
}

// ---------------------------------------------------------------------------
// Ed25519 client authentication
// ---------------------------------------------------------------------------

bool performClientAuth(ITransport       &transport,
                       const std::string &identityPath,
                       bool               isDaemon,
                       bool               verbose,
                       std::string       *errOut,
                       bool               requestCompression,
                       std::uint8_t      *negotiatedCapsOut)
{
    auto setErr  = [&](const char *msg) { if (errOut) *errOut = msg; };
    auto logInfo = [&](const std::string &msg) {
        if (verbose) platform::ntmLog(platform::LogLevel::Info, isDaemon, msg);
    };
    auto logErr  = [&](const std::string &msg) {
        platform::ntmLog(platform::LogLevel::Err, isDaemon, msg);
    };

    if (identityPath.empty())
    {
        logInfo("ntm-client: [auth] no identity file configured — skipping auth");
        return true;
    }

    logInfo("ntm-client: [auth] identity file: " + identityPath);

    if (!platform::checkIdentityFilePermissions(identityPath, isDaemon, verbose))
    {
        setErr("identity key has unsafe permissions or owner — see log for fix");
        return false;
    }

    FILE *fp = std::fopen(identityPath.c_str(), "r");
    if (!fp)
    {
        setErr("cannot open identity file");
        logErr("ntm-client: [auth] cannot open identity file: " + identityPath);
        return false;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    if (!pkey)
    {
        setErr("failed to read Ed25519 private key");
        logErr("ntm-client: [auth] failed to read private key from: " + identityPath);
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519)
    {
        setErr("identity key must be Ed25519");
        logErr("ntm-client: [auth] key type is not Ed25519 (got type id="
               + std::to_string(EVP_PKEY_id(pkey)) + ")");
        EVP_PKEY_free(pkey);
        return false;
    }

    std::size_t pubLen = kAuthPubkeyLen;
    std::uint8_t pubkey[kAuthPubkeyLen];
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubLen) != 1 || pubLen != kAuthPubkeyLen)
    {
        setErr("failed to get public key");
        logErr("ntm-client: [auth] failed to extract Ed25519 public key");
        EVP_PKEY_free(pkey);
        return false;
    }

    if (verbose)
    {
        // Log the first 8 bytes of pubkey so the operator can match it against
        // the server's allowed-keys file without exposing the full key.
        static const char kHex[] = "0123456789abcdef";
        std::string prefix;
        for (int i = 0; i < 8; ++i)
        {
            prefix.push_back(kHex[(pubkey[i] >> 4) & 0xf]);
            prefix.push_back(kHex[pubkey[i] & 0xf]);
        }
        logInfo("ntm-client: [auth] public key prefix (first 8B): " + prefix + "...");
    }

    // ── Step 1: send auth version ────────────────────────────────────────────
    // Auth v3: send version byte, receive 32-byte nonce, send pubkey+sig+caps,
    // receive result byte + negotiated caps byte.
    std::uint8_t version = static_cast<std::uint8_t>(kAuthVersionV3);
    logInfo("ntm-client: [auth] step 1/5 — sending auth version "
            + std::to_string(kAuthVersionV3));
    if (!transport.writeExact(&version, 1))
    {
        setErr("failed to send auth version");
        logErr("ntm-client: [auth] step 1/5 FAILED — could not write version byte "
               "(server closed connection immediately after TLS?)");
        EVP_PKEY_free(pkey);
        return false;
    }

    // ── Step 2: read 32-byte nonce from server ───────────────────────────────
    logInfo("ntm-client: [auth] step 2/5 — reading 32-byte nonce from server...");
    std::uint8_t nonce[kAuthNonceLen];
    if (!transport.readExact(nonce, sizeof(nonce)))
    {
        setErr("failed to read auth nonce");
        logErr("ntm-client: [auth] step 2/5 FAILED — server did not send a nonce "
               "(wrong port? HTTP proxy in the path? server not in wire mode?)");
        EVP_PKEY_free(pkey);
        return false;
    }
    if (verbose)
    {
        static const char kHex[] = "0123456789abcdef";
        std::string nonceHex;
        for (std::size_t i = 0; i < kAuthNonceLen; ++i)
        {
            nonceHex.push_back(kHex[(nonce[i] >> 4) & 0xf]);
            nonceHex.push_back(kHex[nonce[i] & 0xf]);
        }
        logInfo("ntm-client: [auth] step 2/5 ok — nonce: " + nonceHex);
    }

    // ── Step 3: sign nonce ───────────────────────────────────────────────────
    logInfo("ntm-client: [auth] step 3/5 — signing nonce with Ed25519 key...");
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
        logErr("ntm-client: [auth] step 3/5 FAILED — Ed25519 signing error");
        ERR_print_errors_fp(stderr);
        return false;
    }
    logInfo("ntm-client: [auth] step 3/5 ok — signature produced");

    // ── Step 4: send pubkey + signature + capability byte ────────────────────
    const std::uint8_t clientCaps = requestCompression ? kCapZlib : kCapNone;
    char capsBuf[32];
    std::snprintf(capsBuf, sizeof(capsBuf), "0x%02x%s", clientCaps,
                  (clientCaps & kCapZlib) ? " (zlib requested)" : "");
    logInfo(std::string("ntm-client: [auth] step 4/5 — sending pubkey(32B) + sig(64B) + caps(")
            + capsBuf + ")...");

    std::uint8_t msg[kAuthPubkeyLen + kAuthSignatureLen + 1];
    std::memcpy(msg, pubkey, kAuthPubkeyLen);
    std::memcpy(msg + kAuthPubkeyLen, sig, kAuthSignatureLen);
    msg[kAuthPubkeyLen + kAuthSignatureLen] = clientCaps;

    if (!transport.writeExact(msg, sizeof(msg)))
    {
        setErr("failed to send auth message");
        logErr("ntm-client: [auth] step 4/5 FAILED — could not write auth message");
        return false;
    }

    // ── Step 5: read result byte ─────────────────────────────────────────────
    logInfo("ntm-client: [auth] step 5/5 — reading auth result from server...");
    std::uint8_t result = 0xff;
    if (!transport.readExact(&result, 1))
    {
        setErr("failed to read auth result");
        logErr("ntm-client: [auth] step 5/5 FAILED — server closed connection "
               "without sending result (key not registered on server?)");
        return false;
    }
    char resultBuf[64];
    std::snprintf(resultBuf, sizeof(resultBuf), "0x%02x (%s)",
                  result, result == kAuthResultOk ? "accepted" : "REJECTED");
    logInfo(std::string("ntm-client: [auth] step 5/5 — server result: ") + resultBuf);
    if (result != kAuthResultOk)
    {
        setErr("server rejected authentication (key not in server allowed list?)");
        logErr("ntm-client: [auth] authentication rejected — is this client's public key "
               "in the server's allowed_keys file?");
        return false;
    }

    // ── v3: read negotiated capability byte ──────────────────────────────────
    logInfo("ntm-client: [auth] reading negotiated capability byte from server...");
    std::uint8_t negotiatedCaps = kCapNone;
    if (!transport.readExact(&negotiatedCaps, 1))
    {
        setErr("failed to read negotiated capabilities from server");
        logErr("ntm-client: [auth] could not read negotiated caps byte "
               "(server may be too old — pre-v3 auth?)");
        return false;
    }
    char negCapsBuf[64];
    std::snprintf(negCapsBuf, sizeof(negCapsBuf), "0x%02x%s", negotiatedCaps,
                  (negotiatedCaps & kCapZlib) ? " (zlib enabled)" : " (no compression)");
    logInfo(std::string("ntm-client: [auth] negotiated caps: ") + negCapsBuf);
    logInfo("ntm-client: [auth] authentication complete — all steps passed");

    if (negotiatedCapsOut) *negotiatedCapsOut = negotiatedCaps;
    return true;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

// parseConfigLine and loadClientConfig are defined inline in
// client_config_parse.hpp (included above).  No further definitions needed here.

} // namespace ntm
