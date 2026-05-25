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
    /// true when the server capped the entities list. Added in api_version 4; defaults false.
    let truncated: Bool
    let entitiesInternet: [EntityFlow]  // api_version 6 addition; may be absent on v7 servers
    let entitiesLocal: [EntityFlow]     // api_version 6 addition; may be absent on v7 servers
    let localSummary: OverheadSummary?
    let overheadEntities: [EntityFlow]
    /// true when the server capped the overhead_entities list.
    let truncatedOverhead: Bool
    let overheadSummary: OverheadSummary?
    let entitiesLan: [LanDevice]
    /// true when the server capped the entities_lan list.
    let truncatedLan: Bool
    let clientHealth: [ClientHealth]
    let protoRejectedClients: [ProtoRejectedClient]
    /// Per-platform client binaries in the server's update_dir. Added in api_version 7.
    let updateManifest: [UpdateManifest]

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
        case truncated
        case entitiesInternet       = "entities_internet"
        case entitiesLocal          = "entities_local"
        case localSummary           = "local_summary"
        case overheadEntities       = "overhead_entities"
        case truncatedOverhead      = "truncated_overhead"
        case overheadSummary        = "overhead_summary"
        case entitiesLan            = "entities_lan"
        case truncatedLan           = "truncated_lan"
        case clientHealth           = "client_health"
        case protoRejectedClients   = "proto_rejected_clients"
        case updateManifest         = "update_manifest"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        apiVersion             = try c.decodeIfPresent(Int.self,    forKey: .apiVersion)
        serverVersion          = try c.decode(String.self,          forKey: .serverVersion)
        serverWireProtoVersion = try c.decodeIfPresent(Int.self,    forKey: .serverWireProtoVersion)
        demo                   = try c.decodeIfPresent(Bool.self,   forKey: .demo)
        demoExpiresAt          = try c.decodeIfPresent(Int.self,    forKey: .demoExpiresAt)
        windowStart            = try c.decode(Int.self,             forKey: .windowStart)
        generatedAt            = try c.decode(Int.self,             forKey: .generatedAt)
        interfaces             = try c.decode([InterfaceStat].self, forKey: .interfaces)
        entities               = try c.decode([EntityFlow].self,    forKey: .entities)
        truncated              = try c.decodeIfPresent(Bool.self,   forKey: .truncated) ?? false
        // Added in api_version 6 — absent on older servers, default to empty.
        entitiesInternet       = try c.decodeIfPresent([EntityFlow].self,    forKey: .entitiesInternet) ?? []
        entitiesLocal          = try c.decodeIfPresent([EntityFlow].self,    forKey: .entitiesLocal) ?? []
        localSummary           = try c.decodeIfPresent(OverheadSummary.self, forKey: .localSummary)
        overheadEntities       = try c.decodeIfPresent([EntityFlow].self,    forKey: .overheadEntities) ?? []
        truncatedOverhead      = try c.decodeIfPresent(Bool.self,   forKey: .truncatedOverhead) ?? false
        overheadSummary        = try c.decodeIfPresent(OverheadSummary.self, forKey: .overheadSummary)
        entitiesLan            = try c.decodeIfPresent([LanDevice].self,     forKey: .entitiesLan) ?? []
        truncatedLan           = try c.decodeIfPresent(Bool.self,   forKey: .truncatedLan) ?? false
        clientHealth           = try c.decodeIfPresent([ClientHealth].self,  forKey: .clientHealth) ?? []
        protoRejectedClients   = try c.decodeIfPresent([ProtoRejectedClient].self, forKey: .protoRejectedClients) ?? []
        // Added in api_version 7 — absent on older servers, default to empty.
        updateManifest         = try c.decodeIfPresent([UpdateManifest].self, forKey: .updateManifest) ?? []
    }
}
