import Foundation

struct OverheadSummary: Codable, Sendable {
    let packets: Int
    let bytes: Int
    let pctOfTotalBytes: String

    enum CodingKeys: String, CodingKey {
        case packets
        case bytes
        case pctOfTotalBytes = "pct_of_total_bytes"
    }
}

struct DashboardSnapshot: Codable, Sendable {
    let apiVersion: Int?
    let serverVersion: String
    let serverWireProtoVersion: Int?
    let demo: Bool?
    let demoExpiresAt: Int?
    let windowStart: Int
    let generatedAt: Int
    let interfaces: [InterfaceStat]
    let entities: [EntityFlow]
    let overheadEntities: [EntityFlow]
    let overheadSummary: OverheadSummary?
    let entitiesLan: [LanDevice]
    let clientHealth: [ClientHealth]
    let protoRejectedClients: [ProtoRejectedClient]

    enum CodingKeys: String, CodingKey {
        case apiVersion             = "api_version"
        case serverVersion          = "server_version"
        case serverWireProtoVersion = "server_wire_proto_version"
        case demo
        case demoExpiresAt          = "demo_expires_at"
        case windowStart            = "window_start"
        case generatedAt            = "generated_at"
        case interfaces
        case entities
        case overheadEntities       = "overhead_entities"
        case overheadSummary        = "overhead_summary"
        case entitiesLan            = "entities_lan"
        case clientHealth           = "client_health"
        case protoRejectedClients   = "proto_rejected_clients"
    }
}
