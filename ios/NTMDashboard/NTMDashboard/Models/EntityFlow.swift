import Foundation

struct EntityFlow: Codable, Identifiable, Sendable {
    let client: String
    let iface: String
    let srcEntity: String
    let dstEntity: String
    let bytes: Int
    let packets: Int

    var id: String { "\(client)|\(iface)|\(srcEntity)->\(dstEntity)" }

    enum CodingKeys: String, CodingKey {
        case client
        case iface
        case srcEntity = "src_entity"
        case dstEntity = "dst_entity"
        case bytes
        case packets
    }
}
