import Foundation

struct LanDevice: Codable, Identifiable, Sendable {
    let ip: String
    /// WAN IP of the ntm-client that reported this device; "" means same subnet.
    /// Added in api_version 7; defaults to "" on older servers.
    let reportedBy: String
    let outBytes: Int
    let inBytes: Int
    let outPackets: Int
    let inPackets: Int
    /// Not in the formal spec; some server builds emit this from mDNS resolution.
    let hostname: String?

    var id: String { ip }

    enum CodingKeys: String, CodingKey {
        case ip
        case reportedBy = "reported_by"
        case outBytes   = "out_bytes"
        case inBytes    = "in_bytes"
        case outPackets = "out_packets"
        case inPackets  = "in_packets"
        case hostname
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ip         = try c.decode(String.self, forKey: .ip)
        reportedBy = try c.decodeIfPresent(String.self, forKey: .reportedBy) ?? ""
        outBytes   = try c.decode(Int.self, forKey: .outBytes)
        inBytes    = try c.decode(Int.self, forKey: .inBytes)
        outPackets = try c.decode(Int.self, forKey: .outPackets)
        inPackets  = try c.decode(Int.self, forKey: .inPackets)
        hostname   = try c.decodeIfPresent(String.self, forKey: .hostname)
    }
}
