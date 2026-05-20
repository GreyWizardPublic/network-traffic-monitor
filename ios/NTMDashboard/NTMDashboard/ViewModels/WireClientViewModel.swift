import Foundation
import Observation
import UIKit

@Observable
@MainActor
final class WireClientViewModel {

    // MARK: - State

    enum RegistrationStatus {
        case unknown           // key exists but not yet attempted from this session
        case success           // registered on current server this session
        case alreadyRegistered // server says key is already present
    }

    var pubkeyHex: String?           // nil = no key pair stored
    var isLoading = false
    var errorMessage: String?
    var registrationStatus: RegistrationStatus?
    var nickname = UIDevice.current.name

    // Servers (base URL strings) where this key has been registered.
    // Persisted so the UI shows "registered" correctly across app launches.
    private(set) var registeredServers: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: udRegisteredKey) ?? []) }
        set { UserDefaults.standard.set(Array(newValue), forKey: udRegisteredKey) }
    }
    private let udRegisteredKey = "ntm_wire_registered_servers"

    init() {
        pubkeyHex = WireKeyService.publicKeyHex()
    }

    // MARK: - Key management

    func generateKey() {
        WireKeyService.generateKey()
        pubkeyHex = WireKeyService.publicKeyHex()
        // New key — clear prior registration state everywhere
        registeredServers = []
        registrationStatus = nil
        errorMessage = nil
    }

    func regenerateKey() {
        WireKeyService.deleteKey()
        generateKey()
    }

    // Whether the key is already registered on the current server.
    func isRegistered(on serverURL: String) -> Bool {
        registeredServers.contains(serverURL)
    }

    // MARK: - Server registration

    func registerWithServer() async {
        guard let hex = pubkeyHex else { return }
        let cfg = ServerConfig.load()
        guard let base = cfg.baseURL else {
            errorMessage = "Server not configured — add host in Settings"
            return
        }
        let serverURL = base.absoluteString

        isLoading = true
        errorMessage = nil
        registrationStatus = nil
        defer { isLoading = false }

        let pinner = CertificatePinner(pinnedCertData: cfg.pinnedCertData)
        let session = URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)

        var req = URLRequest(
            url: base.appendingPathComponent("/api/admin/client/register"),
            timeoutInterval: 10
        )
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // Attach the passkey session token (or legacy bearer token).
        if let token = KeychainService.loadToken(for: serverURL) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        } else if !cfg.bearerToken.isEmpty {
            req.setValue("Bearer \(cfg.bearerToken)", forHTTPHeaderField: "Authorization")
        }

        struct Body: Encodable {
            let pubkey: String
            let nickname: String
        }
        do {
            req.httpBody = try JSONEncoder().encode(Body(pubkey: hex, nickname: nickname))
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                errorMessage = "Unexpected response type"
                return
            }
            switch http.statusCode {
            case 200:
                registrationStatus = .success
                var updated = registeredServers
                updated.insert(serverURL)
                registeredServers = updated
            case 409:
                registrationStatus = .alreadyRegistered
                var updated = registeredServers
                updated.insert(serverURL)
                registeredServers = updated
            case 401, 403:
                errorMessage = "Not authorised — sign in first, then try again"
            case 404:
                errorMessage = "Endpoint not found — confirm the server has allowed_keys configured"
            default:
                let body = String(data: data, encoding: .utf8) ?? ""
                errorMessage = "Server returned HTTP \(http.statusCode)\(body.isEmpty ? "" : ": \(body)")"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Helpers

    // "abcd1234…efgh5678" — short display form of the 64-hex public key.
    var pubkeyShort: String? {
        guard let h = pubkeyHex, h.count == 64 else { return nil }
        return "\(h.prefix(8))…\(h.suffix(8))"
    }
}
