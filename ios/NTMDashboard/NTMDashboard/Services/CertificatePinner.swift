import Foundation

final class CertificatePinner: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinnedCertData: Data?

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

        guard let pinnedData = pinnedCertData else {
            // No pinning configured — accept based on system trust evaluation
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            return
        }

        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let serverCertData = SecCertificateCopyData(serverCert) as Data
        if serverCertData == pinnedData {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
