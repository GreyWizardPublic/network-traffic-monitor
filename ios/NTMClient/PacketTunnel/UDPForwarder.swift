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

    private struct FlowEntry {
        var conn:         NWConnection
        var lastActivity: Date = .now
    }

    private var flows: [FlowKey: FlowEntry] = [:]

    // Forward a UDP payload toward dstIP:dstPort.
    func forward(packet: IPPacket, rawPayload: Data, into packetFlow: NEPacketTunnelFlow) {
        let key = FlowKey(srcIP: packet.srcIP, srcPort: packet.srcPort,
                          dstIP: packet.dstIP, dstPort: packet.dstPort)

        if var entry = flows[key], isAlive(entry.conn) {
            entry.conn.send(content: rawPayload, completion: .contentProcessed { _ in })
            entry.lastActivity = .now
            flows[key] = entry
        } else {
            let conn = makeConnection(key: key, packetFlow: packetFlow)
            conn.send(content: rawPayload, completion: .contentProcessed { _ in })
            flows[key] = FlowEntry(conn: conn)
        }
    }

    // Remove flows idle for more than idleSecs seconds.
    // Called periodically by PacketTunnelProvider (every ~30 s).
    func sweep(idleSecs: TimeInterval = 60) {
        let cutoff = Date.now.addingTimeInterval(-idleSecs)
        let stale = flows.filter { $0.value.lastActivity < cutoff }
        for key in stale.keys {
            flows[key]?.conn.cancel()
            flows.removeValue(forKey: key)
        }
    }

    // Cancel all open flows (call from stopTunnel).
    func cancelAll() {
        flows.values.forEach { $0.conn.cancel() }
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
                Task { await self?.touchFlow(key: key) }
            }

            if !isComplete, error == nil {
                Task { await self?.receiveLoop(conn: conn, key: key, packetFlow: packetFlow) }
            } else {
                Task { await self?.removeFlow(key: key) }
            }
        }
    }

    private func touchFlow(key: FlowKey) {
        flows[key]?.lastActivity = .now
    }

    private func removeFlow(key: FlowKey) {
        flows.removeValue(forKey: key)
    }
}
