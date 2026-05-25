import CommonCrypto
import CryptoKit
import Foundation
import Observation
import UIKit

@Observable
@MainActor
final class SetupViewModel {

    // MARK: - Persistent config

    var config: ServerConfig = ServerConfig.load() {
        didSet { config.save() }
    }

    // MARK: - Key state

    var pubkeyHex: String?
    var pubkeyShort: String? {
        guard let h = pubkeyHex, h.count == 64 else { return nil }
        return "\(h.prefix(8))…\(h.suffix(8))"
    }

    // MARK: - Registration / session state

    var isSignedIn = false
    var registeredServers: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: udRegKey) ?? []) }
        set { UserDefaults.standard.set(Array(newValue), forKey: udRegKey) }
    }
    private let udRegKey = "ntm_client_registered_servers"

    var isLoading = false
    var errorMessage: String?
    var successMessage: String?

    // TOFU: non-nil while the user is being prompted to trust an untrusted cert.
    var untrustedCertFingerprint: String?
    private var capturedCert: Data?
    private var lastPinner: CertificatePinner?

    private let passkeyService = PasskeyService()
    private static let demoServerURL = "https://ntm.happyhomelives.me:8443"

    // MARK: - Init

    init() {
        pubkeyHex = WireKeyService.publicKeyHex()
        if let url = config.httpsBaseURL?.absoluteString {
            isSignedIn = KeychainService.loadToken(for: url) != nil
        }
    }

    // MARK: - Computed

    var isReadyToConnect: Bool {
        config.isConfigured && !pubkeyHex.isNilOrEmpty && isRegistered
    }

    var isRegistered: Bool {
        guard let url = config.httpsBaseURL?.absoluteString else { return false }
        return registeredServers.contains(url)
    }

    // MARK: - Key management

    func generateKey() {
        WireKeyService.generateKey()
        pubkeyHex = WireKeyService.publicKeyHex()
        registeredServers = []
        errorMessage = nil
        successMessage = nil
    }

    func regenerateKey() {
        WireKeyService.deleteKey()
        generateKey()
    }

    // MARK: - Passkey sign-in

    func login() async {
        guard let base = config.httpsBaseURL else {
            errorMessage = "Server not configured"
            return
        }
        isLoading = true
        errorMessage = nil
        untrustedCertFingerprint = nil
        defer { isLoading = false }

        do {
            let session = makeSession()
            let beginResp = try await fetchLoginChallenge(session: session, base: base)
            guard let challenge = Data(base64URLEncoded: beginResp.challenge) else {
                throw ClientAuthError.invalidServerResponse("bad challenge encoding")
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
            isSignedIn = true
        } catch {
            if isCertError(error), let cert = lastPinner?.lastSeenCert {
                capturedCert = cert
                untrustedCertFingerprint = CertificatePinner.fingerprint(cert)
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    func logout() {
        guard let url = config.httpsBaseURL?.absoluteString else { return }
        KeychainService.deleteToken(for: url)
        isSignedIn = false
    }

    // MARK: - Passkey registration (new device — admin password + device label)

    func register(adminPassword: String, deviceLabel: String) async {
        guard let base = config.httpsBaseURL else {
            errorMessage = "Server not configured"
            return
        }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let session = makeSession()
            let beginResp = try await fetchRegistrationChallenge(session: session, base: base)

            guard
                let salt      = Data(base64URLEncoded: beginResp.pbkdf2Salt),
                let nonce     = Data(base64URLEncoded: beginResp.adminNonce),
                let challenge = Data(base64URLEncoded: beginResp.challenge),
                let userId    = Data(base64URLEncoded: beginResp.userId)
            else {
                throw ClientAuthError.invalidServerResponse("bad registration parameters")
            }

            let proofHex = AdminProof.compute(
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
                throw ClientAuthError.invalidServerResponse("missing attestation object")
            }

            let body = RegisterCompleteBody(
                sessionKey: beginResp.sessionKey,
                adminProof: proofHex,
                attestationObject: attestation.base64URLEncoded,
                clientDataJSON: registration.rawClientDataJSON.base64URLEncoded,
                label: deviceLabel
            )
            var req = URLRequest(url: base.appendingPathComponent("/auth/register/complete"),
                                  timeoutInterval: 10)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(body)
            let (_, resp) = try await session.data(for: req)
            try checkHTTP(resp)

            // Auto-sign-in then auto-register the Ed25519 wire key.
            await login()
            if isSignedIn { await registerKey() }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Ed25519 wire key registration

    func registerKey() async {
        guard let hex = pubkeyHex else {
            errorMessage = "Generate a key pair first"
            return
        }
        guard let base = config.httpsBaseURL else {
            errorMessage = "Server not configured"
            return
        }
        isLoading = true
        errorMessage = nil
        successMessage = nil
        defer { isLoading = false }

        let serverURL = base.absoluteString
        let session = makeSession()
        var req = URLRequest(url: base.appendingPathComponent("/api/admin/client/register"),
                             timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = KeychainService.loadToken(for: serverURL) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let nickname = config.nickname.isEmpty ? UIDevice.current.name : config.nickname

        struct RegBody: Encodable { let pubkey: String; let nickname: String }
        do {
            req.httpBody = try JSONEncoder().encode(RegBody(pubkey: hex, nickname: nickname))
            let (_, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else { return }
            switch http.statusCode {
            case 200, 201:
                successMessage = "Key registered — this device can now connect."
                var s = registeredServers; s.insert(serverURL); registeredServers = s
            case 409:
                successMessage = "Key is already registered on this server."
                var s = registeredServers; s.insert(serverURL); registeredServers = s
            case 401, 403:
                errorMessage = "Not authorised — sign in first"
                isSignedIn = false
            case 404:
                errorMessage = "Endpoint not found — confirm the server has allowed_keys configured"
            default:
                errorMessage = "Server returned HTTP \(http.statusCode)"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Demo mode

    func connectDemo() async {
        isLoading = true
        errorMessage = nil
        untrustedCertFingerprint = nil
        defer { isLoading = false }

        guard let url = URL(string: Self.demoServerURL + "/api/demo/begin") else { return }
        let pinner = CertificatePinner(pinnedCertData: nil)
        lastPinner = pinner
        let session = URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"

        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                errorMessage = "Demo server unavailable"
                return
            }
            guard let decoded = try? JSONDecoder().decode(DemoBeginResponse.self, from: data),
                  !decoded.token.isEmpty else {
                errorMessage = "Unexpected demo server response"
                return
            }
            KeychainService.saveToken(decoded.token, for: Self.demoServerURL)
            config.serverURL = Self.demoServerURL
            // Mark demo server as registered so isReadyToConnect becomes true.
            var s = registeredServers; s.insert(Self.demoServerURL); registeredServers = s
            isSignedIn = true
        } catch {
            if isCertError(error), let cert = lastPinner?.lastSeenCert {
                capturedCert = cert
                untrustedCertFingerprint = CertificatePinner.fingerprint(cert)
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    // MARK: - TOFU cert trust

    func trustCertAndRetry() async {
        guard let cert = capturedCert else { return }
        config.pinnedCertData = cert
        capturedCert = nil
        untrustedCertFingerprint = nil
        await login()
    }

    // MARK: - Cert management

    func clearCert() {
        config.pinnedCertData = nil
    }

    // MARK: - HTTP helpers

    private func makeSession() -> URLSession {
        let pinner = CertificatePinner(pinnedCertData: config.pinnedCertData)
        lastPinner = pinner
        return URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)
    }

    private func fetchRegistrationChallenge(session: URLSession, base: URL) async throws -> RegisterBeginResponse {
        let (data, resp) = try await session.data(for: URLRequest(url: base.appendingPathComponent("/auth/register/begin"), timeoutInterval: 10))
        try checkHTTP(resp)
        return try JSONDecoder().decode(RegisterBeginResponse.self, from: data)
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
            throw ClientAuthError.invalidServerResponse("no token")
        }
        return token
    }

    private func checkHTTP(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse,
              !(200..<300).contains(http.statusCode) else { return }
        throw ClientAuthError.httpError(http.statusCode)
    }

    private func isCertError(_ e: Error) -> Bool {
        let code = (e as NSError).code
        return [NSURLErrorServerCertificateUntrusted,
                NSURLErrorServerCertificateHasUnknownRoot,
                NSURLErrorServerCertificateNotYetValid,
                NSURLErrorServerCertificateHasBadDate].contains(code)
    }
}

// MARK: - Errors

enum ClientAuthError: LocalizedError {
    case httpError(Int)
    case invalidServerResponse(String)

    var errorDescription: String? {
        switch self {
        case .httpError(let code):             return "Server returned HTTP \(code)"
        case .invalidServerResponse(let msg):  return "Unexpected server response: \(msg)"
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
        case adminNonce      = "admin_nonce"
        case pbkdf2Salt      = "pbkdf2_salt"
        case pbkdf2Iterations = "pbkdf2_iterations"
        case rpId    = "rp_id"
        case rpName  = "rp_name"
        case userId  = "user_id"
    }
}

private struct RegisterCompleteBody: Encodable {
    let sessionKey: String
    let adminProof: String
    let attestationObject: String
    let clientDataJSON: String
    let label: String

    enum CodingKeys: String, CodingKey {
        case sessionKey       = "session_key"
        case adminProof       = "admin_proof"
        case attestationObject = "attestation_object"
        case clientDataJSON   = "client_data_json"
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
        case sessionKey       = "session_key"
        case credentialId     = "credential_id"
        case authenticatorData = "authenticator_data"
        case clientDataJSON   = "client_data_json"
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

// MARK: - Base64URL

extension Data {
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
        let r = s.count % 4
        if r != 0 { s += String(repeating: "=", count: 4 - r) }
        guard let d = Data(base64Encoded: s) else { return nil }
        self = d
    }
}

// MARK: - Optional helper

private extension Optional where Wrapped == String {
    var isNilOrEmpty: Bool { self?.isEmpty ?? true }
}
