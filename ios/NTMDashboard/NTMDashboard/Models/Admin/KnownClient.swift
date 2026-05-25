import Foundation

struct KnownClient: Codable, Identifiable, Sendable {
    let clientId: String
    let nickname: String
    let connected: Bool

    var id: String { clientId }

    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case nickname
        case connected
    }
}

struct KnownClientsResponse: Codable, Sendable {
    let clients: [KnownClient]
}
