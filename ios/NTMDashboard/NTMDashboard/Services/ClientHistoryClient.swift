import Foundation

enum HistoryMode: Sendable, Equatable {
    case recent(minutes: Int)  // 1…1440 — fine 1-minute buckets
    case fullWindow            // all hourly buckets across the retention window
}

actor ClientHistoryClient {
    private var config: ServerConfig
    private var session: URLSession

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
    }

    func fetchHistory(clientId: String, mode: HistoryMode) async throws -> ClientHistory {
        guard let base = config.baseURL else { throw NTMError.notConfigured }
        var components = URLComponents(
            url: base.appendingPathComponent("/api/client/history"),
            resolvingAgainstBaseURL: false
        )!
        var queryItems = [URLQueryItem(name: "client_id", value: clientId)]
        if case .recent(let minutes) = mode {
            queryItems.append(URLQueryItem(name: "minutes", value: "\(minutes)"))
        }
        components.queryItems = queryItems

        var req = URLRequest(url: components.url!, timeoutInterval: 10)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token = KeychainService.loadToken(for: base.absoluteString) {
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
            return try JSONDecoder().decode(ClientHistory.self, from: data)
        } catch {
            throw NTMError.decodingError(error)
        }
    }
}
