import Foundation

struct HiddenInterface: Codable, Identifiable, Sendable {
    let clientId: String
    let iface: String

    var id: String { "\(clientId):\(iface)" }

    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case iface
    }
}

struct HiddenEntities: Codable, Sendable {
    let hiddenClients: [String]
    let hiddenInterfaces: [HiddenInterface]

    enum CodingKeys: String, CodingKey {
        case hiddenClients = "hidden_clients"
        case hiddenInterfaces = "hidden_interfaces"
    }
}
