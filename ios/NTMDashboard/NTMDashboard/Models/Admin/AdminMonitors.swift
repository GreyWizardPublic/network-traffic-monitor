import Foundation

struct DashboardClient: Codable, Identifiable, Sendable {
    let ip: String
    let lastSeen: Int
    let active: Bool

    var id: String { "\(ip):\(lastSeen)" }

    enum CodingKeys: String, CodingKey {
        case ip
        case lastSeen = "last_seen"
        case active
    }
}

struct AdminMonitors: Codable, Sendable {
    let wireAgents: [String]
    let dashboardClients: [DashboardClient]

    enum CodingKeys: String, CodingKey {
        case wireAgents = "wire_agents"
        case dashboardClients = "dashboard_clients"
    }
}
