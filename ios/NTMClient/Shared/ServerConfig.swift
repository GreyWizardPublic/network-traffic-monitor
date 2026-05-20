import Foundation

struct ServerConfig: Codable {
    var host: String        // e.g. "ntm.example.com"
    var httpsPort: Int      // HTTPS API port (for key registration), default 8443
    var wirePort: Int       // wire-protocol TCP port, default 5555
    var pinnedCertData: Data?
    var nickname: String    // device nickname sent in registration and H lines

    static let `default` = ServerConfig(
        host: "",
        httpsPort: 8443,
        wirePort: 5555,
        pinnedCertData: nil,
        nickname: ""
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

    var httpsBaseURL: URL? {
        guard !host.isEmpty else { return nil }
        return URL(string: "https://\(host):\(httpsPort)")
    }

    var isConfigured: Bool { !host.isEmpty }
}
