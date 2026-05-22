import CommonCrypto
import CryptoKit
import Foundation
import Observation

@Observable
@MainActor
final class AuthViewModel {
    var isAuthenticated = false
    var isLoading = false
    var errorMessage: String?
    var untrustedCertFingerprint: String?
    var demoUnavailable = false
    var demoErrorDetail: String?

    private let passkeyService = PasskeyService()
    private var capturedCert: Data?
    private var lastPinner: CertificatePinner?
    private var isDemoSession = false

    private static let demoServerURL = "https://ntm.happyhomelives.me:8443"

    init() {
        let cfg = ServerConfig.load()
        if let url = cfg.baseURL?.absoluteString,
           KeychainService.loadToken(for: url) != nil {
            isAuthenticated = true
        }
    }

    func login() async {
        let cfg = ServerConfig.load()
        guard let base = cfg.baseURL else {
            errorMessage = "Server not configured — enter server URL"
            return
        }
        isLoading = true
        errorMessage = nil
        untrustedCertFingerprint = nil
        defer { isLoading = false }

        do {
            let session = makeSession(cfg)

            let beginResp = try await fetchLoginChallenge(session: session, base: base)
            guard let challenge = Data(base64URLEncoded: beginResp.challenge) else {
                throw AuthError.invalidServerResponse("bad challenge encoding")
            }
            let credIds = beginResp.credentialIds.compactMap { Data(base64URLEncoded: $0) }

            let assertion = try await passkeyService.performLogin(
                challenge: challenge,
                rpId: beginResp.rpId,
                allowedCredentialIds: credIds
            )

            let body = LoginCompleteBody(
                sessionKey: beginResp.sessionKey,
                credentialId: assertion.credentialID.base64URLEncoded,
                authenticatorData: assertion.rawAuthenticatorData.base64URLEncoded,
                clientDataJSON: assertion.rawClientDataJSON.base64URLEncoded,
                signature: assertion.signature.base64URLEncoded
            )
            let token = try await completeLogin(session: session, base: base, body: body)

            KeychainService.saveToken(token, for: base.absoluteString)
            isAuthenticated = true
        } catch {
            if isCertError(error), let cert = lastPinner?.lastSeenCert {
                capturedCert = cert
                untrustedCertFingerprint = CertificatePinner.fingerprint(cert)
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    func register(adminPassword: String, deviceLabel: String) async {
        let cfg = ServerConfig.load()
        guard let base = cfg.baseURL else {
            errorMessage = "Server not configured — enter server URL"
            return
        }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let session = makeSession(cfg)

            let beginResp = try await fetchRegistrationChallenge(session: session, base: base)
            guard
                let salt = Data(base64URLEncoded: beginResp.pbkdf2Salt),
                let nonce = Data(base64URLEncoded: beginResp.adminNonce),
                let challenge = Data(base64URLEncoded: beginResp.challenge),
                let userId = Data(base64URLEncoded: beginResp.userId)
            else {
                throw AuthError.invalidServerResponse("bad registration parameters")
            }

            let proofHex = computeAdminProof(
                password: adminPassword,
                salt: salt,
                nonce: nonce,
                iterations: beginResp.pbkdf2Iterations
            )

            let registration = try await passkeyService.performRegistration(
                challenge: challenge,
                rpId: beginResp.rpId,
                userId: userId,
                userName: deviceLabel
            )

            guard let attestation = registration.rawAttestationObject else {
                throw AuthError.invalidServerResponse("missing attestation object")
            }

            let body = RegisterCompleteBody(
                sessionKey: beginResp.sessionKey,
                adminProof: proofHex,
                attestationObject: attestation.base64URLEncoded,
                clientDataJSON: registration.rawClientDataJSON.base64URLEncoded,
                label: deviceLabel
            )
            try await completeRegistration(session: session, base: base, body: body)
            // Registration succeeded — proceed directly to passkey sign-in
            await login()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func trustCertAndRetry() async {
        guard let cert = capturedCert else { return }
        var cfg = ServerConfig.load()
        cfg.pinnedCertData = cert
        cfg.save()
        capturedCert = nil
        untrustedCertFingerprint = nil
        await login()
    }

    func connectDemo() async {
        isLoading = true
        errorMessage = nil
        demoUnavailable = false
        demoErrorDetail = nil
        untrustedCertFingerprint = nil
        defer { isLoading = false }

        guard let url = URL(string: Self.demoServerURL + "/api/demo/begin") else { return }

        // Use CertificatePinner with no pin — accepts the demo server's CA-signed cert
        // without being affected by any cert the user has pinned for their own server.
        let pinner = CertificatePinner(pinnedCertData: nil)
        lastPinner = pinner
        let session = URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"

        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                demoUnavailable = true
                return
            }
            guard http.statusCode == 200 else {
                demoUnavailable = true
                demoErrorDetail = http.statusCode == 503 ? "Demo server is disabled by operator" : "HTTP \(http.statusCode)"
                return
            }
            guard let decoded = try? JSONDecoder().decode(DemoBeginResponse.self, from: data),
                  !decoded.token.isEmpty else {
                demoUnavailable = true
                demoErrorDetail = "Unexpected server response"
                return
            }
            KeychainService.saveToken(decoded.token, for: Self.demoServerURL)
            var cfg = ServerConfig.load()
            cfg.serverURL = Self.demoServerURL
            cfg.save()
            isDemoSession = true
            isAuthenticated = true
        } catch {
            if isCertError(error), let cert = lastPinner?.lastSeenCert {
                capturedCert = cert
                untrustedCertFingerprint = CertificatePinner.fingerprint(cert)
            } else {
                demoUnavailable = true
                demoErrorDetail = (error as NSError).localizedDescription
            }
        }
    }

    func logout() async {
        let cfg = ServerConfig.load()
        let serverURL = cfg.baseURL?.absoluteString ?? ""
        isLoading = true
        defer { isLoading = false }

        if !isDemoSession, let base = cfg.baseURL {
            let token = KeychainService.loadToken(for: serverURL) ?? ""
            try? await performLogout(session: makeSession(cfg), base: base, token: token)
        }
        KeychainService.deleteToken(for: serverURL)
        if isDemoSession {
            var cleanCfg = ServerConfig.load()
            cleanCfg.serverURL = ""
            cleanCfg.save()
            isDemoSession = false
        }
        isAuthenticated = false
    }

    // MARK: - PBKDF2 + HMAC

    private func computeAdminProof(password: String, salt: Data, nonce: Data, iterations: Int) -> String {
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

    // MARK: - HTTP helpers

    private func makeSession(_ cfg: ServerConfig) -> URLSession {
        let pinner = CertificatePinner(pinnedCertData: cfg.pinnedCertData)
        lastPinner = pinner
        return URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)
    }

    private func fetchRegistrationChallenge(session: URLSession, base: URL) async throws -> RegisterBeginResponse {
        let (data, resp) = try await session.data(for: URLRequest(url: base.appendingPathComponent("/auth/register/begin"), timeoutInterval: 10))
        try checkHTTP(resp)
        return try JSONDecoder().decode(RegisterBeginResponse.self, from: data)
    }

    private func completeRegistration(session: URLSession, base: URL, body: RegisterCompleteBody) async throws {
        var req = URLRequest(url: base.appendingPathComponent("/auth/register/complete"), timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(body)
        let (_, resp) = try await session.data(for: req)
        try checkHTTP(resp)
    }

    private func fetchLoginChallenge(session: URLSession, base: URL) async throws -> LoginBeginResponse {
        let (data, resp) = try await session.data(for: URLRequest(url: base.appendingPathComponent("/auth/login/begin"), timeoutInterval: 10))
        try checkHTTP(resp)
        return try JSONDecoder().decode(LoginBeginResponse.self, from: data)
    }

    private func completeLogin(session: URLSession, base: URL, body: LoginCompleteBody) async throws -> String {
        var req = URLRequest(url: base.appendingPathComponent("/auth/login/complete"), timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(body)
        let (data, resp) = try await session.data(for: req)
        try checkHTTP(resp)
        let decoded = try JSONDecoder().decode(LoginCompleteResponse.self, from: data)
        guard let token = decoded.token else {
            throw AuthError.invalidServerResponse("no token in response")
        }
        return token
    }

    private func performLogout(session: URLSession, base: URL, token: String) async throws {
        var req = URLRequest(url: base.appendingPathComponent("/auth/logout"), timeoutInterval: 10)
        req.httpMethod = "POST"
        if !token.isEmpty {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let (_, resp) = try await session.data(for: req)
        try checkHTTP(resp)
    }

    private func checkHTTP(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse, http.statusCode != 200 else { return }
        throw AuthError.httpError(http.statusCode)
    }

    private func isCertError(_ e: Error) -> Bool {
        let code = (e as NSError).code
        return [NSURLErrorServerCertificateUntrusted,
                NSURLErrorServerCertificateHasUnknownRoot,
                NSURLErrorServerCertificateNotYetValid,
                NSURLErrorServerCertificateHasBadDate].contains(code)
    }
}

// MARK: - Error

enum AuthError: LocalizedError {
    case httpError(Int)
    case invalidServerResponse(String)

    var errorDescription: String? {
        switch self {
        case .httpError(let code): return "Server returned HTTP \(code)"
        case .invalidServerResponse(let detail): return "Unexpected server response: \(detail)"
        }
    }
}

// MARK: - Response / request models

private struct RegisterBeginResponse: Decodable {
    let sessionKey: String
    let challenge: String
    let adminNonce: String
    let pbkdf2Salt: String
    let pbkdf2Iterations: Int
    let rpId: String
    let rpName: String
    let userId: String

    enum CodingKeys: String, CodingKey {
        case sessionKey = "session_key"
        case challenge
        case adminNonce = "admin_nonce"
        case pbkdf2Salt = "pbkdf2_salt"
        case pbkdf2Iterations = "pbkdf2_iterations"
        case rpId = "rp_id"
        case rpName = "rp_name"
        case userId = "user_id"
    }
}

private struct RegisterCompleteBody: Encodable {
    let sessionKey: String
    let adminProof: String
    let attestationObject: String
    let clientDataJSON: String
    let label: String

    enum CodingKeys: String, CodingKey {
        case sessionKey = "session_key"
        case adminProof = "admin_proof"
        case attestationObject = "attestation_object"
        case clientDataJSON = "client_data_json"
        case label
    }
}

private struct LoginBeginResponse: Decodable {
    let sessionKey: String
    let challenge: String
    let rpId: String
    let credentialIds: [String]

    enum CodingKeys: String, CodingKey {
        case sessionKey = "session_key"
        case challenge
        case rpId = "rp_id"
        case credentialIds = "credential_ids"
    }
}

private struct LoginCompleteBody: Encodable {
    let sessionKey: String
    let credentialId: String
    let authenticatorData: String
    let clientDataJSON: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case sessionKey = "session_key"
        case credentialId = "credential_id"
        case authenticatorData = "authenticator_data"
        case clientDataJSON = "client_data_json"
        case signature
    }
}

private struct LoginCompleteResponse: Decodable {
    let ok: Bool
    let token: String?
}

private struct DemoBeginResponse: Decodable {
    let ok: Bool
    let token: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case ok
        case token
        case expiresIn = "expires_in"
    }
}

// MARK: - Base64URL helpers

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded string: String) {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder != 0 { s += String(repeating: "=", count: 4 - remainder) }
        guard let d = Data(base64Encoded: s) else { return nil }
        self = d
    }
}
