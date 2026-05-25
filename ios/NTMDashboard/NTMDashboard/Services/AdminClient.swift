import Foundation

actor AdminClient {
    private var config: ServerConfig
    private var session: URLSession
    private var adminProofToken: String?
    private var adminProofIssuedAt: Date?

    private let tokenTTL: TimeInterval = 1800  // kAdminProofTokenSec

    init(config: ServerConfig) {
        self.config = config
        self.session = URLSession(
            configuration: .ephemeral,
            delegate: CertificatePinner(pinnedCertData: config.pinnedCertData),
            delegateQueue: nil
        )
    }

    func updateConfig(_ newConfig: ServerConfig) {
        config = newConfig
        session = URLSession(
            configuration: .ephemeral,
            delegate: CertificatePinner(pinnedCertData: newConfig.pinnedCertData),
            delegateQueue: nil
        )
        adminProofToken = nil
        adminProofIssuedAt = nil
    }

    var isAdminAuthenticated: Bool {
        guard let token = adminProofToken, !token.isEmpty,
              let issued = adminProofIssuedAt else { return false }
        return Date().timeIntervalSince(issued) < tokenTTL
    }

    // MARK: - Auth

    func authenticate(password: String) async throws {
        guard let base = config.baseURL else { throw NTMError.notConfigured }
        let url = base.appendingPathComponent("/api/admin/auth")
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token = KeychainService.loadToken(for: base.absoluteString) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        req.httpBody = try JSONEncoder().encode(["password": password])

        let (_, response) = try await perform(req)
        guard let http = response as? HTTPURLResponse else { return }
        if http.statusCode != 200 { throw NTMError.httpError(http.statusCode) }

        // Extract ntm_admin cookie from Set-Cookie header
        if let setCookie = http.value(forHTTPHeaderField: "Set-Cookie") {
            let parts = setCookie.split(separator: ";")
            if let first = parts.first {
                let kv = first.split(separator: "=", maxSplits: 1)
                if kv.count == 2, kv[0].trimmingCharacters(in: .whitespaces) == "ntm_admin" {
                    adminProofToken = String(kv[1])
                    adminProofIssuedAt = Date()
                }
            }
        }
    }

    // MARK: - Admin API methods

    func monitors() async throws -> AdminMonitors {
        let data = try await authorizedGet("/api/admin/monitors")
        return try decode(AdminMonitors.self, from: data)
    }

    func clients() async throws -> [KnownClient] {
        let data = try await authorizedGet("/api/admin/clients")
        return try decode(KnownClientsResponse.self, from: data).clients
    }

    func hiddenEntities() async throws -> HiddenEntities {
        let data = try await authorizedGet("/api/admin/hidden")
        return try decode(HiddenEntities.self, from: data)
    }

    func setHiddenClient(_ clientId: String, hidden: Bool) async throws {
        let body: [String: String] = [
            "client_id": clientId,
            "action": hidden ? "hide" : "unhide"
        ]
        try await authorizedPost("/api/admin/hidden/client", body: body)
    }

    func setHiddenInterface(clientId: String, iface: String, hidden: Bool) async throws {
        let body: [String: String] = [
            "client_id": clientId,
            "iface": iface,
            "action": hidden ? "hide" : "unhide"
        ]
        try await authorizedPost("/api/admin/hidden/interface", body: body)
    }

    func purgeClient(_ client: String) async throws {
        try await authorizedPost("/api/admin/purge", body: ["client": client])
    }

    func scanUpdates() async throws -> Int {
        struct ScanResult: Decodable { let ok: Bool; let count: Int }
        let data = try await authorizedPost("/api/admin/update/scan", body: [String: String]())
        let result = try decode(ScanResult.self, from: data)
        return result.count
    }

    func forceUpdate(pubkey: String) async throws {
        try await authorizedPost("/api/admin/update/force", body: ["pubkey": pubkey])
    }

    func setDemoEnabled(_ enabled: Bool) async throws {
        try await authorizedPost("/api/admin/demo", body: ["enabled": enabled])
    }

    // MARK: - Helpers

    @discardableResult
    private func authorizedPost<T: Encodable>(_ path: String, body: T) async throws -> Data {
        guard let base = config.baseURL else { throw NTMError.notConfigured }
        var req = URLRequest(url: base.appendingPathComponent(path), timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        addAuth(to: &req, base: base)
        req.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await perform(req)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw NTMError.httpError(http.statusCode)
        }
        return data
    }

    private func authorizedGet(_ path: String) async throws -> Data {
        guard let base = config.baseURL else { throw NTMError.notConfigured }
        var req = URLRequest(url: base.appendingPathComponent(path), timeoutInterval: 10)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        addAuth(to: &req, base: base)
        let (data, response) = try await perform(req)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw NTMError.httpError(http.statusCode)
        }
        return data
    }

    private func addAuth(to req: inout URLRequest, base: URL) {
        if let token = KeychainService.loadToken(for: base.absoluteString) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let proof = adminProofToken, isAdminAuthenticated {
            req.setValue("ntm_admin=\(proof)", forHTTPHeaderField: "Cookie")
        }
    }

    private func perform(_ req: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: req)
        } catch {
            throw NTMError.networkError(error)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw NTMError.decodingError(error)
        }
    }
}
