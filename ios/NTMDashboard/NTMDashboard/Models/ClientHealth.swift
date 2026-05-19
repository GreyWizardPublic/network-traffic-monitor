import Foundation

struct ClientHealth: Codable, Identifiable, Sendable {
    let client: String
    let ver: String
    let uptimeSec: Int
    let pcapDropPct: String
    let ifaces: [String]

    var id: String { client }

    enum CodingKeys: String, CodingKey {
        case client
        case ver
        case uptimeSec   = "uptime_sec"
        case pcapDropPct = "pcap_drop_pct"
        case ifaces
    }
}
