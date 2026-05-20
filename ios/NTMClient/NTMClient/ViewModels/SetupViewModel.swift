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

    var pubkeyHex: String?     // nil = no key generated
    var pubkeyShort: String? {
        guard let h = pubkeyHex, h.count == 64 else { return nil }
        return "\(h.prefix(8))…\(h.suffix(8))"
    }

    // MARK: - Registration state

    var isSignedIn = false     // has a valid passkey session token
    var registeredServers: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: udRegKey) ?? []) }
        set { UserDefaults.standard.set(Array(newValue), forKey: udRegKey) }
    }
    private let udRegKey = "ntm_client_registered_servers"

    var isLoading = false
    var errorMessage: String?
    var successMessage: String?

    private let passkeyService = PasskeyService()

    // MARK: - Init

    init() {
        pubkeyHex = WireKeyService.publicKeyHex()
        if let url = config.httpsBaseURL?.absoluteString {
            isSignedIn = KeychainService.loadToken(for: url) != nil
        }
    }

    // MARK: - Computed

    var isReadyToConnect: Bool {
        config.isConfigured
            && !pubkeyHex.isNilOrEmpty
            && isRegistered
    }

    var isRegistered: Bool {
        guard let url = config.httpsBaseURL?.absoluteString else { return false }
        return registeredServers.contains(url)
    }

    // MARK: - Key management

    func generateKey() {
        WireKeyService.generateKey()
        pubkeyHex = WireKeyService.publicKeyHex()
        // New key — clear prior registration state
        registeredServers = []
        errorMessage = nil
        successMessage = nil
    }

    func regenerateKey() {
        WireKeyService.deleteKey()
        generateKey()
    }

    // MARK: - Passkey login (needed to call /api/admin/client/register)

    func login() async {
        guard let base = config.httpsBaseURL else {
            errorMessage = "Server not configured"
            return
        }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let session = makeSession()
            let beginData = try await get(session: session,
                                          url: base.appendingPathComponent("/auth/login/begin"))
            let beginResp = try JSONDecoder().decode(LoginBeginResponse.self, from: beginData)
            guard let challenge = Data(base64URLEncoded: beginResp.challenge) else {
                throw ClientAuthError.invalidServerResponse("bad challenge")
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
            let respData = try await post(session: session,
                                          url: base.appendingPathComponent("/auth/login/complete"),
                                          body: body)
            let loginResp = try JSONDecoder().decode(LoginCompleteResponse.self, from: respData)
            guard let token = loginResp.token else {
                throw ClientAuthError.invalidServerResponse("no token")
            }
            KeychainService.saveToken(token, for: base.absoluteString)
            isSignedIn = true
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func logout() {
        guard let url = config.httpsBaseURL?.absoluteString else { return }
        KeychainService.deleteToken(for: url)
        isSignedIn = false
    }

    // MARK: - Server registration

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
            case 200:
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

    // MARK: - Cert import

    func importCert(data: Data) {
        config.pinnedCertData = data
    }

    func clearCert() {
        config.pinnedCertData = nil
    }

    // MARK: - HTTP helpers

    private func makeSession() -> URLSession {
        URLSession(configuration: .ephemeral,
                   delegate: CertificatePinner(pinnedCertData: config.pinnedCertData),
                   delegateQueue: nil)
    }

    private func get(session: URLSession, url: URL) async throws -> Data {
        let (data, resp) = try await session.data(for: URLRequest(url: url, timeoutInterval: 10))
        try checkHTTP(resp)
        return data
    }

    private func post(session: URLSession, url: URL, body: some Encodable) async throws -> Data {
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(body)
        let (data, resp) = try await session.data(for: req)
        try checkHTTP(resp)
        return data
    }

    private func checkHTTP(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse, http.statusCode != 200 else { return }
        throw ClientAuthError.httpError(http.statusCode)
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
