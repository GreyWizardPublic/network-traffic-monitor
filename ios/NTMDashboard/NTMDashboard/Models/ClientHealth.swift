import Foundation

struct ClientHealth: Codable, Identifiable, Sendable {
    let client: String
    let version: String
    let pcapRecv: Int
    let pcapDrop: Int
    let pcapDropPct: String
    let bufDrop: Int
    let reportedAt: Int
    let stale: Bool

    var id: String { client }

    enum CodingKeys: String, CodingKey {
        case client
        case version
        case pcapRecv    = "pcap_recv"
        case pcapDrop    = "pcap_drop"
        case pcapDropPct = "pcap_drop_pct"
        case bufDrop     = "buf_drop"
        case reportedAt  = "reported_at"
        case stale
    }
}
