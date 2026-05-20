import Foundation

enum NTMError: Error, LocalizedError {
    case notConfigured
    case httpError(Int)
    case decodingError(Error)
    case networkError(Error)

    var errorDescription: String? {
        switch self {
        case .notConfigured:        return "Server not configured — enter server URL"
        case .httpError(let code):  return "HTTP \(code)"
        case .decodingError(let e): return "Decode error: \(e.localizedDescription)"
        case .networkError(let e):  return e.localizedDescription
        }
    }
}

actor NTMClient {
    private var config: ServerConfig
    private var session: URLSession

    init(config: ServerConfig) {
        self.config = config
        let pinner = CertificatePinner(pinnedCertData: config.pinnedCertData)
        self.session = URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)
    }

    func updateConfig(_ newConfig: ServerConfig) {
        config = newConfig
        let pinner = CertificatePinner(pinnedCertData: newConfig.pinnedCertData)
        session = URLSession(configuration: .ephemeral, delegate: pinner, delegateQueue: nil)
    }

    func fetchSummary() async throws -> DashboardSnapshot {
        guard let base = config.baseURL else { throw NTMError.notConfigured }
        let url = base.appendingPathComponent("/api/summary")
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if !config.bearerToken.isEmpty {
            req.setValue("Bearer \(config.bearerToken)", forHTTPHeaderField: "Authorization")
        } else if let token = KeychainService.loadToken(for: base.absoluteString) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw NTMError.networkError(error)
        }

        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw NTMError.httpError(http.statusCode)
        }

        do {
            return try JSONDecoder().decode(DashboardSnapshot.self, from: data)
        } catch {
            throw NTMError.decodingError(error)
        }
    }
}
