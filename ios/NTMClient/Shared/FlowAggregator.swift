import Foundation

// Accumulates IPPacket observations by (srcIP, dstIP) and produces aggregated
// D-lines on demand.  Thread-safe via NSLock; observe() is called synchronously
// from the NEPacketTunnelFlow read callback, drain() from a periodic timer task.
//
// This avoids the per-packet Task{} fan-out that overloads the cooperative pool
// and causes silent drops when the server's ~20k lines/s ingest limit is exceeded.
final class FlowAggregator: @unchecked Sendable {

    private struct FlowKey: Hashable {
        let srcIP: String
        let dstIP: String
    }

    private var flows: [FlowKey: UInt64] = [:]
    private let lock = NSLock()

    // Called from the packet-read callback — must be fast and non-blocking.
    func observe(_ packet: IPPacket) {
        lock.lock(); defer { lock.unlock() }
        flows[FlowKey(srcIP: packet.srcIP, dstIP: packet.dstIP), default: 0]
            &+= UInt64(packet.totalBytes)
    }

    // Atomically snapshots and resets the accumulator.
    // Returns aggregated D-lines ready to send, and the count of distinct flows.
    func drain() -> (lines: [String], flowCount: Int) {
        lock.lock()
        let snapshot = flows
        flows = [:]
        lock.unlock()

        let lines = snapshot.map { key, bytes in
            "D utun \(key.srcIP) \(key.dstIP) \(bytes)"
        }
        return (lines, lines.count)
    }
}
