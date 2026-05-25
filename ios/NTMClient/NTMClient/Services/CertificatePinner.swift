import CryptoKit
import Foundation

final class CertificatePinner: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinnedCertData: Data?
    // Always populated with the server's leaf cert DER when a TLS challenge fires.
    // Used by SetupViewModel's TOFU flow to capture and pin an untrusted cert.
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
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        }
    }

    // SHA-256 of the cert's DER bytes, first 8 pairs shown as "XX:XX:…".
    static func fingerprint(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02X", $0) }
        return hex.prefix(8).joined(separator: ":") + "…"
    }
}
