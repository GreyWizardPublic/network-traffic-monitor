import Foundation

struct ServerConfig {
    // HTTPS base URL, e.g. "https://ntm.home.me:8443". Mirrors NTMDashboard.
    var serverURL: String
    // Wire-protocol TCP/WS port (separate from HTTPS port; default 5555).
    var wirePort: Int
    var pinnedCertData: Data?
    var nickname: String
    // When true the tunnel connects via wss://<host>:<wirePort>/wire (Cloudflare compat).
    var useWebSocket: Bool

    static let `default` = ServerConfig(
        serverURL: "",
        wirePort: 5555,
        pinnedCertData: nil,
        nickname: "",
        useWebSocket: false
    )

    private static let udKey = "ntm_client_server_config"

    static func load() -> ServerConfig {
        guard let data = UserDefaults.standard.data(forKey: udKey),
              let cfg = try? JSONDecoder().decode(ServerConfig.self, from: data)
        else { return .default }
        return cfg
    }

    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        UserDefaults.standard.set(data, forKey: Self.udKey)
    }

    // HTTPS base URL derived from serverURL (accepts bare hostname or partial URL).
    var httpsBaseURL: URL? {
        guard !serverURL.isEmpty else { return nil }
        var s = serverURL
        if !s.hasPrefix("https://") && !s.hasPrefix("http://") { s = "https://" + s }
        if s.hasSuffix("/") { s = String(s.dropLast()) }
        return URL(string: s)
    }

    // Hostname for the raw wire-protocol connection.
    var wireHost: String? { httpsBaseURL?.host }

    var isConfigured: Bool { httpsBaseURL != nil }
}

extension ServerConfig: Codable {
    enum CodingKeys: String, CodingKey {
        case serverURL
        case wirePort
        case pinnedCertData
        case nickname
        case useWebSocket
        // Legacy keys from the host+httpsPort era
        case legacyHost      = "host"
        case legacyHttpsPort = "httpsPort"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)

        // Migration: prefer new serverURL; fall back to legacy host+httpsPort.
        if let url = try c.decodeIfPresent(String.self, forKey: .serverURL), !url.isEmpty {
            serverURL = url
        } else {
            let h = try c.decodeIfPresent(String.self, forKey: .legacyHost) ?? ""
            let p = try c.decodeIfPresent(Int.self, forKey: .legacyHttpsPort) ?? 8443
            serverURL = h.isEmpty ? "" : "https://\(h):\(p)"
        }

        // The old config used "wirePort" as the primary key — read it directly.
        wirePort       = try c.decodeIfPresent(Int.self,    forKey: .wirePort)       ?? 5555
        pinnedCertData = try c.decodeIfPresent(Data.self,   forKey: .pinnedCertData)
        nickname       = try c.decodeIfPresent(String.self, forKey: .nickname)       ?? ""
        useWebSocket   = try c.decodeIfPresent(Bool.self,   forKey: .useWebSocket)   ?? false
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverURL,    forKey: .serverURL)
        try c.encode(wirePort,     forKey: .wirePort)
        try c.encodeIfPresent(pinnedCertData, forKey: .pinnedCertData)
        try c.encode(nickname,     forKey: .nickname)
        try c.encode(useWebSocket, forKey: .useWebSocket)
    }
}
