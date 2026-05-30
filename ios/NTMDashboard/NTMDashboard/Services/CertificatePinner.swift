import CryptoKit
import Foundation

final class CertificatePinner: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinnedCertData: Data?
    private(set) var lastSeenCert: Data?

    init(pinnedCertData: Data?) {
        self.pinnedCertData = pinnedCertData
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Always capture leaf cert so TOFU flow can inspect it after failure
        if let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
           let first = chain.first {
            lastSeenCert = SecCertificateCopyData(first) as Data
        }

        if let pinned = pinnedCertData {
            if lastSeenCert == pinned {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            // No pin stored yet — reject to prevent silent MITM on first connection.
            // The caller catches the resulting cert error, reads lastSeenCert, and
            // presents the fingerprint to the user for explicit TOFU confirmation.
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    static func fingerprint(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02X", $0) }
        return hex.prefix(8).joined(separator: ":") + "…"
    }
}
