import CommonCrypto
import CryptoKit
import Foundation

/// PBKDF2-HMAC-SHA256 admin proof used in the passkey registration flow.
///
/// The server never receives the admin password in plaintext. Instead the client
/// derives a 32-byte key with PBKDF2, then computes an HMAC-SHA256 over the
/// server-supplied nonce, and sends the result as a 64-char lowercase hex string.
///
/// Reference: api-protocol.md § 7 `GET /auth/register/begin`.
enum AdminProof {
    /// Compute the admin proof for passkey registration.
    ///
    /// - Parameters:
    ///   - password:   Plain-text admin password (never sent to the server).
    ///   - salt:       16-byte PBKDF2 salt from the server's `/auth/register/begin` response.
    ///   - nonce:      32-byte admin nonce from the server's `/auth/register/begin` response.
    ///   - iterations: PBKDF2 iteration count from the server response (typically 200 000).
    /// - Returns: 64 lowercase hex characters (32-byte HMAC-SHA256 output).
    static func compute(password: String, salt: Data, nonce: Data, iterations: Int) -> String {
        var derivedKey = Data(count: 32)
        derivedKey.withUnsafeMutableBytes { derivedBytes in
            password.withCString { passwordPtr in
                salt.withUnsafeBytes { saltBytes in
                    _ = CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr, strlen(passwordPtr),
                        saltBytes.baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedBytes.baseAddress, 32
                    )
                }
            }
        }
        let key = SymmetricKey(data: derivedKey)
        let mac = HMAC<SHA256>.authenticationCode(for: nonce, using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }
}
