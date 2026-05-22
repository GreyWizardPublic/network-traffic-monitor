import Foundation

struct ProtoRejectedClient: Codable, Identifiable, Sendable {
    let peerIp: String
    let attemptedAuthVersion: Int
    let at: Int

    var id: String { "\(peerIp)-\(at)" }

    enum CodingKeys: String, CodingKey {
        case peerIp              = "peer_ip"
        case attemptedAuthVersion = "attempted_auth_version"
        case at
    }
}
