import Foundation

struct InterfaceStat: Codable, Identifiable, Sendable {
    let client: String
    let iface: String
    let packets: Int
    let bytes: Int

    var id: String { "\(client)/\(iface)" }
}
