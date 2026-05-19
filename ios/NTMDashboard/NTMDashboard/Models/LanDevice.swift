import Foundation

struct LanDevice: Codable, Identifiable, Sendable {
    let ip: String
    let outBytes: Int
    let inBytes: Int
    let outPackets: Int
    let inPackets: Int
    let hostname: String?

    var id: String { ip }

    enum CodingKeys: String, CodingKey {
        case ip
        case outBytes   = "out_bytes"
        case inBytes    = "in_bytes"
        case outPackets = "out_packets"
        case inPackets  = "in_packets"
        case hostname
    }
}
