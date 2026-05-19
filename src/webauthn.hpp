#pragma once
// WebAuthn RP: passkey registration, authentication, and session management.
// Self-contained — depends only on OpenSSL (already linked) and the standard library.

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ntm
{

struct WebAuthnConfig
{
    std::string rpId;               // e.g. "ntm.happyhomelives.me" — empty disables WebAuthn
    std::string rpName;             // display name shown during registration
    std::string credentialsFile;    // JSON file that persists registered passkey credentials
    std::string adminCredFile;      // JSON file storing PBKDF2 admin credential hash
    std::string iosAppId;           // "<TeamID>.<BundleID>" for AASA (empty = no AASA)
    std::vector<std::string> allowedOrigins; // e.g. {"https://ntm.happyhomelives.me"}
    unsigned sessionTtlHours{24};
};

struct PasskeyCredential
{
    std::string credId;        // base64url credential ID
    std::string pubkeyX;       // base64url P-256 x coordinate (32 bytes)
    std::string pubkeyY;       // base64url P-256 y coordinate (32 bytes)
    std::uint32_t signCount{0};
    std::string label;         // human-readable device name
};

// Thread-safe WebAuthn Relying Party.
class WebAuthnRP
{
public:
    explicit WebAuthnRP(WebAuthnConfig cfg);
    ~WebAuthnRP() = default;

    bool enabled() const { return !cfg_.rpId.empty(); }

    // --- Registration ---
    // Returns JSON to send to the client. sessionKey is the opaque pending-session ID.
    std::string beginRegistration(std::string &sessionKey);

    // Verify admin PBKDF2 proof + WebAuthn attestationObject.
    // Returns "" on success, error string on failure.
    std::string completeRegistration(const std::string &sessionKey,
                                     const std::string &adminProofHex,
                                     const std::string &attestationObjectB64,
                                     const std::string &clientDataJsonB64,
                                     const std::string &label);

    // --- Authentication ---
    // Returns JSON challenge to send to the client.
    std::string beginAuthentication(std::string &sessionKey);

    // Verify WebAuthn assertion. On success returns a session token; errorOut is set on failure.
    std::string completeAuthentication(const std::string &sessionKey,
                                       const std::string &credentialIdB64,
                                       const std::string &authenticatorDataB64,
                                       const std::string &clientDataJsonB64,
                                       const std::string &signatureB64,
                                       std::string &errorOut);

    // --- Session management ---
    bool isValidSession(const std::string &token) const;
    void invalidateSession(const std::string &token);

    // --- Admin credential management ---
    // Hash plaintext password with PBKDF2 and persist to adminCredFile.
    std::string migrateAdminPassword(const std::string &plaintext);

    // --- Credential listing / deletion (admin UI) ---
    std::vector<PasskeyCredential> listCredentials() const;
    bool deleteCredential(const std::string &credId);

    // Returns the Apple App Site Association JSON, or "" if iosAppId is not set.
    std::string aasaJson() const;

    bool hasAdminCred() const;

private:
    WebAuthnConfig cfg_;

    struct PendingReg
    {
        std::vector<uint8_t> webauthnChallenge; // for navigator.credentials.create()
        std::vector<uint8_t> adminNonce;        // for PBKDF2 proof
        std::chrono::steady_clock::time_point expiry;
    };

    struct PendingAuth
    {
        std::vector<uint8_t> challenge;
        std::chrono::steady_clock::time_point expiry;
    };

    struct Session
    {
        std::chrono::steady_clock::time_point expiry;
    };

    struct AdminCred
    {
        std::vector<uint8_t> hash;      // 32-byte PBKDF2-HMAC-SHA256(password, salt, iterations)
        std::vector<uint8_t> salt;      // 16-byte random salt
        unsigned iterations{200000};
    };

    mutable std::mutex mtx_;
    std::unordered_map<std::string, PendingReg>  pendingRegs_;
    std::unordered_map<std::string, PendingAuth> pendingAuths_;
    std::unordered_map<std::string, Session>     sessions_;
    std::vector<PasskeyCredential>               credentials_;
    std::optional<AdminCred>                     adminCred_;

    void loadCredentials();
    void saveCredentials() const;    // call holding mtx_
    void loadAdminCred();
    void sweepExpired();             // call holding mtx_

    static std::vector<uint8_t> randomBytes(std::size_t n);
    static std::string          toBase64url(const uint8_t *data, std::size_t len);
    static std::string          toBase64url(const std::vector<uint8_t> &v);
    static std::vector<uint8_t> fromBase64url(const std::string &s);
    static std::string          bytesToHex(const uint8_t *data, std::size_t len);
    static std::vector<uint8_t> hexToBytes(const std::string &hex);
    static std::vector<uint8_t> sha256(const uint8_t *data, std::size_t len);
    static std::string          jsonGetStr(const std::string &json, const std::string &key);

    bool extractAuthDataFromAttestationObject(const std::vector<uint8_t> &attObj,
                                               std::vector<uint8_t> &authDataOut) const;

    bool parseAuthData(const std::vector<uint8_t> &authData,
                       std::string &credIdOut,
                       std::vector<uint8_t> &pubXOut,
                       std::vector<uint8_t> &pubYOut,
                       uint32_t &signCountOut,
                       bool expectAT) const;

    bool extractCoseP256(const uint8_t *data, std::size_t len,
                         std::vector<uint8_t> &xOut, std::vector<uint8_t> &yOut) const;

    bool verifyEcdsaP256(const std::vector<uint8_t> &pubX,
                         const std::vector<uint8_t> &pubY,
                         const std::vector<uint8_t> &msg,
                         const std::vector<uint8_t> &derSig) const;
};

} // namespace ntm
