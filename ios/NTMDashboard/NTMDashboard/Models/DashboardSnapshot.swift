import Foundation

struct DashboardSnapshot: Codable, Sendable {
    let apiVersion: Int?
    let serverVersion: String
    let windowStart: Int
    let generatedAt: Int
    let interfaces: [InterfaceStat]
    let entities: [EntityFlow]
    let entitiesLan: [LanDevice]
    let clientHealth: [ClientHealth]

    enum CodingKeys: String, CodingKey {
        case apiVersion    = "api_version"
        case serverVersion = "server_version"
        case windowStart   = "window_start"
        case generatedAt   = "generated_at"
        case interfaces
        case entities
        case entitiesLan   = "entities_lan"
        case clientHealth  = "client_health"
    }
}
