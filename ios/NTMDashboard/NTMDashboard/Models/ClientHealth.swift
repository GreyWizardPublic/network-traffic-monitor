import Foundation

struct ClientHealth: Codable, Identifiable, Sendable {
    let client: String
    /// Stable identity: raw 64-hex Ed25519 public key. Added in api_version 7.
    let clientId: String?
    let version: String
    /// e.g. "linux-amd64" or "windows-amd64". Added in api_version 7.
    let platform: String?
    let pcapRecv: Int
    let pcapDrop: Int
    let pcapDropPct: String
    let bufDrop: Int
    /// buf_drop as a % of pcap_recv, formatted "N.NN". Added in api_version 7;
    /// defaults to "0.00" on older servers that omit it.
    let bufDropPct: String
    let reportedAt: Int
    let stale: Bool
    // Optional — present only after the client's first H-line includes wire_proto=N
    let wireProtoVersion: Int?
    let wireProtoOk: Bool?
    // Added in ntm-client 1.10.0 / ntm-server 1.13.0 — absent on older clients
    let aggIntervalMs: Int?
    let aggFlows: Int?

    var id: String { clientId ?? client }

    enum CodingKeys: String, CodingKey {
        case client
        case clientId        = "client_id"
        case version
        case platform
        case pcapRecv        = "pcap_recv"
        case pcapDrop        = "pcap_drop"
        case pcapDropPct     = "pcap_drop_pct"
        case bufDrop         = "buf_drop"
        case bufDropPct      = "buf_drop_pct"
        case reportedAt      = "reported_at"
        case stale
        case wireProtoVersion = "wire_proto_version"
        case wireProtoOk     = "wire_proto_ok"
        case aggIntervalMs   = "agg_interval_ms"
        case aggFlows        = "agg_flows"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        client           = try c.decode(String.self, forKey: .client)
        clientId         = try c.decodeIfPresent(String.self, forKey: .clientId)
        version          = try c.decode(String.self, forKey: .version)
        platform         = try c.decodeIfPresent(String.self, forKey: .platform)
        pcapRecv         = try c.decode(Int.self,    forKey: .pcapRecv)
        pcapDrop         = try c.decode(Int.self,    forKey: .pcapDrop)
        pcapDropPct      = try c.decode(String.self, forKey: .pcapDropPct)
        bufDrop          = try c.decode(Int.self,    forKey: .bufDrop)
        bufDropPct       = try c.decodeIfPresent(String.self, forKey: .bufDropPct) ?? "0.00"
        reportedAt       = try c.decode(Int.self,    forKey: .reportedAt)
        stale            = try c.decode(Bool.self,   forKey: .stale)
        wireProtoVersion = try c.decodeIfPresent(Int.self,  forKey: .wireProtoVersion)
        wireProtoOk      = try c.decodeIfPresent(Bool.self, forKey: .wireProtoOk)
        aggIntervalMs    = try c.decodeIfPresent(Int.self,  forKey: .aggIntervalMs)
        aggFlows         = try c.decodeIfPresent(Int.self,  forKey: .aggFlows)
    }
}
