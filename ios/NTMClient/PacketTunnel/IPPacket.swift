import Darwin
import Foundation

// Parsed representation of one IP packet from packetFlow.readPackets.
struct IPPacket {
    let version: Int           // 4 or 6
    let proto: UInt8           // 6=TCP, 17=UDP, etc.
    let srcIP: String
    let dstIP: String
    let totalBytes: Int        // full IP packet size — used as 'bytes' field in D-line
    let ihlBytes: Int          // IPv4 IHL in bytes (0 for IPv6)
    // UDP port fields; zero for non-UDP packets
    let srcPort: UInt16
    let dstPort: UInt16
    // Byte range of the UDP payload within the original Data passed to parse().
    let udpPayloadRange: Range<Int>

    static let protoUDP: UInt8 = 17

    // D-line for this packet (wire protocol data phase).
    var dLine: String { "D utun \(srcIP) \(dstIP) \(totalBytes)" }

    // Returns the UDP application payload slice, or nil if not UDP / empty.
    func udpPayload(in data: Data) -> Data? {
        guard proto == IPPacket.protoUDP,
              !udpPayloadRange.isEmpty,
              udpPayloadRange.upperBound <= data.count else { return nil }
        return data[udpPayloadRange]
    }

    // Parse a raw IP packet. `af` is AF_INET (2) or AF_INET6 (30).
    static func parse(_ data: Data, af: Int32) -> IPPacket? {
        if af == AF_INET  { return parseIPv4(data) }
        if af == AF_INET6 { return parseIPv6(data) }
        return nil
    }

    // MARK: - IPv4

    private static func parseIPv4(_ data: Data) -> IPPacket? {
        let b = Array(data)
        guard b.count >= 20 else { return nil }
        guard (b[0] >> 4) == 4 else { return nil }
        let ihl = Int(b[0] & 0x0F) * 4
        guard ihl >= 20, b.count >= ihl else { return nil }

        let totalLen = Int(UInt16(b[2]) << 8 | UInt16(b[3]))
        let proto    = b[9]
        let srcIP    = "\(b[12]).\(b[13]).\(b[14]).\(b[15])"
        let dstIP    = "\(b[16]).\(b[17]).\(b[18]).\(b[19])"

        var srcPort: UInt16 = 0
        var dstPort: UInt16 = 0
        var udpPayloadRange: Range<Int> = 0..<0

        if proto == protoUDP, b.count >= ihl + 8 {
            srcPort = UInt16(b[ihl])     << 8 | UInt16(b[ihl + 1])
            dstPort = UInt16(b[ihl + 2]) << 8 | UInt16(b[ihl + 3])
            let udpLen      = Int(UInt16(b[ihl + 4]) << 8 | UInt16(b[ihl + 5]))
            let payloadStart = ihl + 8
            let payloadEnd   = min(payloadStart + max(0, udpLen - 8), b.count)
            if payloadStart < payloadEnd { udpPayloadRange = payloadStart..<payloadEnd }
        }

        return IPPacket(version: 4, proto: proto, srcIP: srcIP, dstIP: dstIP,
                        totalBytes: totalLen, ihlBytes: ihl,
                        srcPort: srcPort, dstPort: dstPort,
                        udpPayloadRange: udpPayloadRange)
    }

    // MARK: - IPv6

    private static func parseIPv6(_ data: Data) -> IPPacket? {
        let b = Array(data)
        guard b.count >= 40 else { return nil }
        guard (b[0] >> 4) == 6 else { return nil }

        let payloadLen = Int(UInt16(b[4]) << 8 | UInt16(b[5]))
        let nextHeader = b[6]
        let totalLen   = 40 + payloadLen

        let srcIP = formatIPv6(b, offset: 8)
        let dstIP = formatIPv6(b, offset: 24)

        var srcPort: UInt16 = 0
        var dstPort: UInt16 = 0
        var udpPayloadRange: Range<Int> = 0..<0

        // Simple: no extension header handling — treat nextHeader directly as transport
        if nextHeader == protoUDP, b.count >= 48 {
            srcPort = UInt16(b[40]) << 8 | UInt16(b[41])
            dstPort = UInt16(b[42]) << 8 | UInt16(b[43])
            let udpLen       = Int(UInt16(b[44]) << 8 | UInt16(b[45]))
            let payloadStart = 48
            let payloadEnd   = min(payloadStart + max(0, udpLen - 8), b.count)
            if payloadStart < payloadEnd { udpPayloadRange = payloadStart..<payloadEnd }
        }

        return IPPacket(version: 6, proto: nextHeader, srcIP: srcIP, dstIP: dstIP,
                        totalBytes: totalLen, ihlBytes: 0,
                        srcPort: srcPort, dstPort: dstPort,
                        udpPayloadRange: udpPayloadRange)
    }

    private static func formatIPv6(_ b: [UInt8], offset: Int) -> String {
        (0..<8).map { i -> String in
            let w = UInt16(b[offset + i * 2]) << 8 | UInt16(b[offset + i * 2 + 1])
            return String(w, radix: 16)
        }.joined(separator: ":")
    }
}

// Builds a raw IPv4+UDP packet suitable for writing back into packetFlow.
// srcIP/srcPort: the remote server (becomes the IP source in the injected packet).
// dstIP/dstPort: the original sender / local app (becomes the IP destination).
func buildIPv4UDPReply(srcIP: String, srcPort: UInt16,
                       dstIP: String, dstPort: UInt16,
                       payload: Data) -> Data? {
    let srcParts = srcIP.split(separator: ".").compactMap { UInt8($0) }
    let dstParts = dstIP.split(separator: ".").compactMap { UInt8($0) }
    guard srcParts.count == 4, dstParts.count == 4 else { return nil }
    guard payload.count <= 65527 else { return nil }  // max UDP payload

    let udpLen   = UInt16(8 + payload.count)
    let totalLen = UInt16(20 + Int(udpLen))

    var pkt = [UInt8](repeating: 0, count: Int(totalLen))

    // IPv4 header (checksum field left zero until calculated below)
    pkt[0]  = 0x45                          // version=4, IHL=5
    pkt[2]  = UInt8(totalLen >> 8)
    pkt[3]  = UInt8(totalLen & 0xFF)
    pkt[6]  = 0x40                          // flags: DF
    pkt[8]  = 64                            // TTL
    pkt[9]  = 17                            // protocol: UDP
    pkt[12] = srcParts[0]; pkt[13] = srcParts[1]
    pkt[14] = srcParts[2]; pkt[15] = srcParts[3]
    pkt[16] = dstParts[0]; pkt[17] = dstParts[1]
    pkt[18] = dstParts[2]; pkt[19] = dstParts[3]

    let ipCk = onesComplementChecksum(pkt, start: 0, count: 20)
    pkt[10]  = UInt8(ipCk >> 8)
    pkt[11]  = UInt8(ipCk & 0xFF)

    // UDP header (checksum field left zero until calculated below)
    pkt[20] = UInt8(srcPort >> 8); pkt[21] = UInt8(srcPort & 0xFF)
    pkt[22] = UInt8(dstPort >> 8); pkt[23] = UInt8(dstPort & 0xFF)
    pkt[24] = UInt8(udpLen >> 8);  pkt[25] = UInt8(udpLen & 0xFF)

    // UDP payload
    for (i, byte) in payload.enumerated() { pkt[28 + i] = byte }

    // UDP checksum: IPv4 pseudo-header + UDP segment (checksum field is still 0)
    var pseudo = [UInt8]()
    pseudo.reserveCapacity(12 + Int(udpLen))
    pseudo.append(contentsOf: srcParts)    // src IP (4 B)
    pseudo.append(contentsOf: dstParts)    // dst IP (4 B)
    pseudo.append(0x00)                    // zero
    pseudo.append(0x11)                    // protocol: UDP
    pseudo.append(UInt8(udpLen >> 8))
    pseudo.append(UInt8(udpLen & 0xFF))
    pseudo.append(contentsOf: pkt[20...]) // UDP header + payload (checksum=0)

    let udpCk = onesComplementChecksum(pseudo, start: 0, count: pseudo.count)
    pkt[26]   = UInt8(udpCk >> 8)
    pkt[27]   = UInt8(udpCk & 0xFF)

    return Data(pkt)
}

// RFC 1071 one's-complement sum checksum (network byte order: high byte first).
private func onesComplementChecksum(_ bytes: [UInt8], start: Int, count: Int) -> UInt16 {
    var sum: UInt32 = 0
    var i = start
    let end = start + count
    while i + 1 < end {
        sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
        i += 2
    }
    if i < end {
        sum += UInt32(bytes[i]) << 8  // odd trailing byte treated as high byte
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
    return ~UInt16(truncatingIfNeeded: sum)
}
