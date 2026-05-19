import Foundation

struct EntityFlow: Codable, Identifiable, Sendable {
    let srcEntity: String
    let dstEntity: String
    let bytes: Int
    let packets: Int

    var id: String { "\(srcEntity)->\(dstEntity)" }

    enum CodingKeys: String, CodingKey {
        case srcEntity = "src_entity"
        case dstEntity = "dst_entity"
        case bytes
        case packets
    }
}
