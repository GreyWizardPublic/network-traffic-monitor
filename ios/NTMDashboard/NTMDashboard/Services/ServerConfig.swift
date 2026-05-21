import Foundation

struct ServerConfig {
    var serverURL: String        // e.g. "https://ntm.home.me:8443"
    var pinnedCertData: Data?
    var pollingIntervalSec: Int

    static let `default` = ServerConfig(
        serverURL: "",
        pinnedCertData: nil,
        pollingIntervalSec: 5
    )

    private static let udKey = "ntm_server_config"

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

    var baseURL: URL? {
        guard !serverURL.isEmpty else { return nil }
        var s = serverURL
        if !s.hasPrefix("https://") && !s.hasPrefix("http://") { s = "https://" + s }
        if s.hasSuffix("/") { s = String(s.dropLast()) }
        return URL(string: s)
    }

    var isConfigured: Bool { baseURL != nil }
}

extension ServerConfig: Codable {
    enum CodingKeys: String, CodingKey {
        case serverURL
        case pinnedCertData
        case pollingIntervalSec
        case legacyHost = "host"
        case legacyPort = "port"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Migrate from old host+port format
        if let url = try c.decodeIfPresent(String.self, forKey: .serverURL), !url.isEmpty {
            serverURL = url
        } else {
            let h = try c.decodeIfPresent(String.self, forKey: .legacyHost) ?? ""
            let p = try c.decodeIfPresent(Int.self, forKey: .legacyPort) ?? 8443
            serverURL = h.isEmpty ? "" : "https://\(h):\(p)"
        }
        pinnedCertData = try c.decodeIfPresent(Data.self, forKey: .pinnedCertData)
        pollingIntervalSec = try c.decodeIfPresent(Int.self, forKey: .pollingIntervalSec) ?? 5
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverURL, forKey: .serverURL)
        try c.encodeIfPresent(pinnedCertData, forKey: .pinnedCertData)
        try c.encode(pollingIntervalSec, forKey: .pollingIntervalSec)
    }
}
