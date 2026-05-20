import Foundation
import Network
import NetworkExtension

// Per-flow TCP relay. One NWConnection(.tcp) per (srcIP, srcPort, dstIP, dstPort) 4-tuple.
// NWConnections created inside the extension process bypass the tunnel automatically.
actor TCPRelay {

    struct FlowKey: Hashable {
        let srcIP:   String
        let srcPort: UInt16
        let dstIP:   String
        let dstPort: UInt16
    }

    private struct FlowState {
        var conn:           NWConnection
        var clientSeqNext:  UInt32   // next seq we expect from the client
        var serverSeqNext:  UInt32   // next seq we send toward the client
        var clientFinSeen:  Bool = false
    }

    private var flows: [FlowKey: FlowState] = [:]

    // Entry point: called for every IPv4 TCP packet read from packetFlow.
    func handlePacket(pkt: IPPacket, tcp: TCPHeader, rawData: Data,
                      packetFlow: NEPacketTunnelFlow) {
        let key = FlowKey(srcIP: pkt.srcIP, srcPort: tcp.srcPort,
                          dstIP: pkt.dstIP, dstPort: tcp.dstPort)

        if tcp.isRST {
            closeFlow(key: key)
            return
        }

        if tcp.isSYN && !tcp.isACK {
            // New connection request.
            openFlow(key: key, clientISN: tcp.seq, packetFlow: packetFlow)
            return
        }

        guard var state = flows[key] else { return }

        // Forward payload to server.
        if tcp.payloadLen > 0 {
            let payload = rawData[tcp.payloadRange]
            state.conn.send(content: payload,
                            completion: .contentProcessed { _ in })
        }

        // Client FIN: signal EOF to the server side.
        if tcp.isFIN, !state.clientFinSeen {
            state.clientFinSeen = true
            state.clientSeqNext &+= 1
            // Half-close toward server.
            state.conn.send(content: nil,
                            contentContext: .defaultMessage,
                            isComplete: true,
                            completion: .idempotent)
        }

        // Advance client sequence tracker.
        if tcp.payloadLen > 0 {
            state.clientSeqNext = tcp.seq &+ UInt32(tcp.payloadLen)
        }

        flows[key] = state
    }

    // Cancel all open flows (called from stopTunnel).
    func cancelAll() {
        flows.values.forEach { $0.conn.cancel() }
        flows.removeAll()
    }

    // MARK: - Private

    private func openFlow(key: FlowKey, clientISN: UInt32,
                          packetFlow: NEPacketTunnelFlow) {
        // Close any stale flow for this key first.
        flows[key]?.conn.cancel()

        let serverISN = UInt32.random(in: 0...UInt32.max)
        let clientSeqNext: UInt32 = clientISN &+ 1   // SYN consumes one seq

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(key.dstIP),
            port: NWEndpoint.Port(rawValue: key.dstPort)!
        )
        let conn = NWConnection(to: endpoint, using: .tcp)

        let state = FlowState(conn: conn,
                              clientSeqNext: clientSeqNext,
                              serverSeqNext: serverISN &+ 1)
        flows[key] = state

        // Send SYN-ACK immediately so the client doesn't time out while
        // the NWConnection is connecting asynchronously.
        sendToClient(key: key, seq: serverISN, ack: clientSeqNext,
                     flags: 0x12 /* SYN+ACK */, payload: Data(),
                     packetFlow: packetFlow)

        conn.stateUpdateHandler = { [weak self] connState in
            guard case .failed = connState else { return }
            Task { await self?.sendRST(key: key, packetFlow: packetFlow) }
            Task { await self?.closeFlow(key: key) }
        }

        conn.start(queue: .global(qos: .utility))
        receiveFromServer(conn: conn, key: key, packetFlow: packetFlow)
    }

    private func receiveFromServer(conn: NWConnection, key: FlowKey,
                                   packetFlow: NEPacketTunnelFlow) {
        conn.receive(minimumIncompleteLength: 1,
                     maximumLength: 65495) { [weak self] data, _, isComplete, error in
            Task { await self?.onServerData(key: key, data: data,
                                            isComplete: isComplete, error: error,
                                            conn: conn, packetFlow: packetFlow) }
        }
    }

    private func onServerData(key: FlowKey, data: Data?, isComplete: Bool,
                               error: NWError?, conn: NWConnection,
                               packetFlow: NEPacketTunnelFlow) {
        guard var state = flows[key] else { return }

        if let data, !data.isEmpty {
            sendToClient(key: key,
                         seq: state.serverSeqNext,
                         ack: state.clientSeqNext,
                         flags: 0x18 /* PSH+ACK */,
                         payload: data,
                         packetFlow: packetFlow)
            state.serverSeqNext = state.serverSeqNext &+ UInt32(data.count)
            flows[key] = state
        }

        if error != nil {
            sendRST(key: key, packetFlow: packetFlow)
            closeFlow(key: key)
            return
        }

        if isComplete {
            // Server closed its write side — send FIN+ACK to client.
            sendToClient(key: key,
                         seq: state.serverSeqNext,
                         ack: state.clientSeqNext,
                         flags: 0x11 /* FIN+ACK */,
                         payload: Data(),
                         packetFlow: packetFlow)
            closeFlow(key: key)
            return
        }

        // Continue receiving.
        receiveFromServer(conn: conn, key: key, packetFlow: packetFlow)
    }

    // Injects a raw IP+TCP packet toward the client (srcIP/srcPort = the remote server).
    // Detects IP version from the address format (IPv6 contains ":").
    private func sendToClient(key: FlowKey, seq: UInt32, ack: UInt32,
                               flags: UInt8, payload: Data,
                               packetFlow: NEPacketTunnelFlow) {
        let isIPv6 = key.dstIP.contains(":")
        let pkt: Data?
        let af: Int32
        if isIPv6 {
            pkt = buildTCPv6Packet(
                srcIP: key.dstIP, srcPort: key.dstPort,
                dstIP: key.srcIP, dstPort: key.srcPort,
                seq: seq, ack: ack, flags: flags, window: 65535,
                payload: payload)
            af = AF_INET6
        } else {
            pkt = buildTCPv4Packet(
                srcIP: key.dstIP, srcPort: key.dstPort,
                dstIP: key.srcIP, dstPort: key.srcPort,
                seq: seq, ack: ack, flags: flags, window: 65535,
                payload: payload)
            af = AF_INET
        }
        guard let pkt else { return }
        packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: af)])
    }

    private func sendRST(key: FlowKey, packetFlow: NEPacketTunnelFlow) {
        guard let state = flows[key] else { return }
        sendToClient(key: key,
                     seq: state.serverSeqNext,
                     ack: state.clientSeqNext,
                     flags: 0x14 /* RST+ACK */,
                     payload: Data(),
                     packetFlow: packetFlow)
    }

    private func closeFlow(key: FlowKey) {
        flows[key]?.conn.cancel()
        flows.removeValue(forKey: key)
    }
}
