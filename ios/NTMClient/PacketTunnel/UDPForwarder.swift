import Foundation
import Network
@preconcurrency import NetworkExtension

// Per-flow UDP relay. One NWConnection per (srcIP, srcPort, dstIP, dstPort) 4-tuple.
// NWConnections created inside a NEPacketTunnelProvider process bypass the tunnel
// automatically (Apple's extension routing bypass) — no routing loop risk.
actor UDPForwarder {

    struct FlowKey: Hashable {
        let srcIP: String
        let srcPort: UInt16
        let dstIP: String
        let dstPort: UInt16
    }

    private var flows: [FlowKey: NWConnection] = [:]

    // Forward a UDP payload toward dstIP:dstPort.
    // On receipt of a reply the reply is reconstructed as a raw IPv4+UDP packet
    // and injected back into the tunnel via packetFlow.writePackets.
    func forward(packet: IPPacket, rawPayload: Data, into packetFlow: NEPacketTunnelFlow) {
        let key = FlowKey(srcIP: packet.srcIP, srcPort: packet.srcPort,
                          dstIP: packet.dstIP, dstPort: packet.dstPort)

        let conn: NWConnection
        if let existing = flows[key], isAlive(existing) {
            conn = existing
        } else {
            conn = makeConnection(key: key, packetFlow: packetFlow)
            flows[key] = conn
        }

        conn.send(content: rawPayload, completion: .contentProcessed { _ in })
    }

    // Cancel all open flows (call from stopTunnel).
    func cancelAll() {
        flows.values.forEach { $0.cancel() }
        flows.removeAll()
    }

    // MARK: - Private

    private func isAlive(_ conn: NWConnection) -> Bool {
        switch conn.state {
        case .ready, .preparing, .setup, .waiting: return true
        default: return false
        }
    }

    private func makeConnection(key: FlowKey, packetFlow: NEPacketTunnelFlow) -> NWConnection {
        let endpoint = NWEndpoint.hostPort(
            host:  NWEndpoint.Host(key.dstIP),
            port:  NWEndpoint.Port(rawValue: key.dstPort)!
        )
        let conn = NWConnection(to: endpoint, using: .udp)
        conn.start(queue: .global(qos: .utility))
        receiveLoop(conn: conn, key: key, packetFlow: packetFlow)
        return conn
    }

    private func receiveLoop(conn: NWConnection, key: FlowKey, packetFlow: NEPacketTunnelFlow) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                // Build a reply packet: src = remote server, dst = original sender.
                // Detect IP version from the address format (IPv6 contains ":").
                let isIPv6 = key.dstIP.contains(":")
                let reply: Data?
                let af: Int32
                if isIPv6 {
                    reply = buildIPv6UDPReply(
                        srcIP: key.dstIP, srcPort: key.dstPort,
                        dstIP: key.srcIP, dstPort: key.srcPort,
                        payload: data)
                    af = AF_INET6
                } else {
                    reply = buildIPv4UDPReply(
                        srcIP: key.dstIP, srcPort: key.dstPort,
                        dstIP: key.srcIP, dstPort: key.srcPort,
                        payload: data)
                    af = AF_INET
                }
                if let reply {
                    packetFlow.writePackets([reply], withProtocols: [NSNumber(value: af)])
                }
            }

            if !isComplete, error == nil {
                Task { await self?.receiveLoop(conn: conn, key: key, packetFlow: packetFlow) }
            } else {
                Task { await self?.removeFlow(key: key) }
            }
        }
    }

    private func removeFlow(key: FlowKey) {
        flows.removeValue(forKey: key)
    }
}
