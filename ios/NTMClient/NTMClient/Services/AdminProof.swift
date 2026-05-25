import CommonCrypto
import CryptoKit
import Foundation

// PBKDF2-HMAC-SHA256 admin proof for passkey registration.
// The server never receives the admin password; instead the client derives a 32-byte
// key with PBKDF2, computes HMAC-SHA256 over the server nonce, and sends the hex result.
// Reference: docs/api-protocol.md § 7 GET /auth/register/begin.
enum AdminProof {
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
