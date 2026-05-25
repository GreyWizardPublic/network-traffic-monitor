import Foundation

struct HistoryBucket: Codable, Identifiable, Sendable {
    let t: Int          // unix epoch of bucket start
    let inBytes: Int    // inbound bytes (WAN→LAN direction)
    let outBytes: Int   // outbound bytes (LAN→WAN + LAN→LAN)
    let inPackets: Int
    let outPackets: Int

    var id: Int { t }

    enum CodingKeys: String, CodingKey {
        case t
        case inBytes    = "in_bytes"
        case outBytes   = "out_bytes"
        case inPackets  = "in_packets"
        case outPackets = "out_packets"
    }
}

struct ClientHistory: Codable, Sendable {
    let clientId: String
    let bucketSeconds: Int   // 60 for fine ring, 3600 for coarse ring
    let windowDays: Int
    let buckets: [HistoryBucket]

    enum CodingKeys: String, CodingKey {
        case clientId      = "client_id"
        case bucketSeconds = "bucket_seconds"
        case windowDays    = "window_days"
        case buckets
    }
}
