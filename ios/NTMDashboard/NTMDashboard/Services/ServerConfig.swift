import Foundation

struct ServerConfig: Codable {
    var host: String
    var port: Int
    var bearerToken: String
    var pinnedCertData: Data?
    var pollingIntervalSec: Int

    static let `default` = ServerConfig(
        host: "",
        port: 8443,
        bearerToken: "",
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
        guard !host.isEmpty else { return nil }
        return URL(string: "https://\(host):\(port)")
    }
}
