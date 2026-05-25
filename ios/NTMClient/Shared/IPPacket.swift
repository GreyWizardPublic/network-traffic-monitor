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
    // Byte offset of the transport-layer header within the original packet Data.
    // For IPv4: same as ihlBytes. For IPv6: 40 + any extension headers.
    let transportOffset: Int
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
                        totalBytes: totalLen, ihlBytes: ihl, transportOffset: ihl,
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

        // Walk RFC 8200 extension headers to reach the transport-layer protocol.
        let (transport, tOff) = walkIPv6ExtHeaders(b, nextHeader: nextHeader, offset: 40)

        var srcPort: UInt16 = 0
        var dstPort: UInt16 = 0
        var udpPayloadRange: Range<Int> = 0..<0

        if transport == protoUDP, b.count >= tOff + 8 {
            srcPort = UInt16(b[tOff])     << 8 | UInt16(b[tOff + 1])
            dstPort = UInt16(b[tOff + 2]) << 8 | UInt16(b[tOff + 3])
            let udpLen       = Int(UInt16(b[tOff + 4]) << 8 | UInt16(b[tOff + 5]))
            let payloadStart = tOff + 8
            let payloadEnd   = min(payloadStart + max(0, udpLen - 8), b.count)
            if payloadStart < payloadEnd { udpPayloadRange = payloadStart..<payloadEnd }
        }

        return IPPacket(version: 6, proto: transport, srcIP: srcIP, dstIP: dstIP,
                        totalBytes: totalLen, ihlBytes: 0, transportOffset: tOff,
                        srcPort: srcPort, dstPort: dstPort,
                        udpPayloadRange: udpPayloadRange)
    }

    private static func formatIPv6(_ b: [UInt8], offset: Int) -> String {
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { dst in
            for i in 0..<16 { dst[i] = b[offset + i] }
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return withUnsafePointer(to: &addr) { ptr in
            inet_ntop(AF_INET6, ptr, &buf, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buf)
        }
    }

    // Walk RFC 8200 §4 extension headers and return (transport protocol, transport offset).
    // Handled extension header types: Hop-by-Hop (0), Routing (43), Fragment (44),
    // Destination Options (60). Stops at the first unrecognised type.
    private static func walkIPv6ExtHeaders(_ b: [UInt8], nextHeader: UInt8,
                                           offset: Int) -> (UInt8, Int) {
        var nh  = nextHeader
        var off = offset
        while true {
            switch nh {
            case 0, 43, 60:     // Hop-by-Hop / Routing / Dest Options: variable length
                guard b.count > off + 1 else { return (nh, off) }
                let extLen = (Int(b[off + 1]) + 1) * 8
                nh  = b[off]
                off += extLen
            case 44:            // Fragment header: fixed 8 bytes
                guard b.count > off else { return (nh, off) }
                nh  = b[off]
                off += 8
            default:            // Transport-layer protocol or unrecognised extension
                return (nh, off)
            }
        }
    }
}

// MARK: - TCP header

struct TCPHeader {
    let srcPort:    UInt16
    let dstPort:    UInt16
    let seq:        UInt32
    let ack:        UInt32
    let headerBytes: Int        // TCP header length in bytes (data offset field × 4)
    let flags:      UInt8       // flags byte: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
    let window:     UInt16
    let payloadRange: Range<Int> // range of TCP payload within the original packet Data

    var isSYN: Bool { flags & 0x02 != 0 }
    var isACK: Bool { flags & 0x10 != 0 }
    var isFIN: Bool { flags & 0x01 != 0 }
    var isRST: Bool { flags & 0x04 != 0 }
    var payloadLen: Int { payloadRange.count }
}

extension IPPacket {
    // Parse the TCP header from a raw IPv4 or IPv6 packet. Returns nil for non-TCP packets
    // or packets that are too short.
    func parseTCP(in data: Data) -> TCPHeader? {
        guard proto == 6 else { return nil }
        let b = Array(data)
        let t = transportOffset
        guard b.count >= t + 20 else { return nil }

        let srcPort  = UInt16(b[t])     << 8 | UInt16(b[t +  1])
        let dstPort  = UInt16(b[t + 2]) << 8 | UInt16(b[t +  3])
        let seq      = UInt32(b[t + 4]) << 24 | UInt32(b[t +  5]) << 16
                     | UInt32(b[t + 6]) <<  8 | UInt32(b[t +  7])
        let ack      = UInt32(b[t + 8]) << 24 | UInt32(b[t +  9]) << 16
                     | UInt32(b[t + 10]) <<  8 | UInt32(b[t + 11])
        let dataOff  = Int(b[t + 12] >> 4) * 4
        let flags    = b[t + 13]
        let window   = UInt16(b[t + 14]) << 8 | UInt16(b[t + 15])

        guard dataOff >= 20, b.count >= t + dataOff else { return nil }

        let payloadStart = t + dataOff
        let payloadEnd   = min(b.count, max(payloadStart, totalBytes))
        let payloadRange = payloadStart..<payloadEnd

        return TCPHeader(srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack,
                         headerBytes: dataOff, flags: flags, window: window,
                         payloadRange: payloadRange)
    }
}

// Builds a raw IPv4+TCP packet for injecting into packetFlow.
// No TCP options are added (data offset = 5, header = 20 bytes).
func buildTCPv4Packet(srcIP: String, srcPort: UInt16,
                       dstIP: String, dstPort: UInt16,
                       seq: UInt32, ack: UInt32,
                       flags: UInt8, window: UInt16,
                       payload: Data = Data()) -> Data? {
    let srcParts = srcIP.split(separator: ".").compactMap { UInt8($0) }
    let dstParts = dstIP.split(separator: ".").compactMap { UInt8($0) }
    guard srcParts.count == 4, dstParts.count == 4 else { return nil }
    guard payload.count <= 65495 else { return nil }  // 65535 - 20 (IP) - 20 (TCP)

    let tcpLen   = UInt16(20 + payload.count)
    let totalLen = UInt16(20 + Int(tcpLen))

    var pkt = [UInt8](repeating: 0, count: Int(totalLen))

    // IPv4 header (checksum calculated below)
    pkt[ 0] = 0x45                          // version=4, IHL=5
    pkt[ 2] = UInt8(totalLen >> 8)
    pkt[ 3] = UInt8(totalLen & 0xFF)
    pkt[ 6] = 0x40                          // flags: DF
    pkt[ 8] = 64                            // TTL
    pkt[ 9] = 6                             // protocol: TCP
    pkt[12] = srcParts[0]; pkt[13] = srcParts[1]
    pkt[14] = srcParts[2]; pkt[15] = srcParts[3]
    pkt[16] = dstParts[0]; pkt[17] = dstParts[1]
    pkt[18] = dstParts[2]; pkt[19] = dstParts[3]

    let ipCk = onesComplementChecksum(pkt, start: 0, count: 20)
    pkt[10]  = UInt8(ipCk >> 8)
    pkt[11]  = UInt8(ipCk & 0xFF)

    // TCP header (checksum calculated below)
    pkt[20] = UInt8(srcPort >> 8); pkt[21] = UInt8(srcPort & 0xFF)
    pkt[22] = UInt8(dstPort >> 8); pkt[23] = UInt8(dstPort & 0xFF)
    pkt[24] = UInt8(seq >> 24);    pkt[25] = UInt8((seq >> 16) & 0xFF)
    pkt[26] = UInt8((seq >> 8) & 0xFF); pkt[27] = UInt8(seq & 0xFF)
    pkt[28] = UInt8(ack >> 24);    pkt[29] = UInt8((ack >> 16) & 0xFF)
    pkt[30] = UInt8((ack >> 8) & 0xFF); pkt[31] = UInt8(ack & 0xFF)
    pkt[32] = 0x50                          // data offset = 5 (20 bytes)
    pkt[33] = flags
    pkt[34] = UInt8(window >> 8); pkt[35] = UInt8(window & 0xFF)
    // pkt[36-37]: checksum; pkt[38-39]: urgent pointer = 0

    for (i, b) in payload.enumerated() { pkt[40 + i] = b }

    // TCP checksum: IPv4 pseudo-header + TCP segment (checksum field = 0)
    var pseudo = [UInt8]()
    pseudo.reserveCapacity(12 + Int(tcpLen))
    pseudo.append(contentsOf: srcParts)    // src IP
    pseudo.append(contentsOf: dstParts)    // dst IP
    pseudo.append(0x00)                    // zero
    pseudo.append(0x06)                    // protocol: TCP
    pseudo.append(UInt8(tcpLen >> 8))
    pseudo.append(UInt8(tcpLen & 0xFF))
    pseudo.append(contentsOf: pkt[20...]) // TCP header + payload (checksum field = 0)

    let tcpCk = onesComplementChecksum(pseudo, start: 0, count: pseudo.count)
    pkt[36]   = UInt8(tcpCk >> 8)
    pkt[37]   = UInt8(tcpCk & 0xFF)

    return Data(pkt)
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

// Builds a raw IPv6+TCP packet for injecting into packetFlow.
// No TCP options are added (data offset = 5, header = 20 bytes).
func buildTCPv6Packet(srcIP: String, srcPort: UInt16,
                       dstIP: String, dstPort: UInt16,
                       seq: UInt32, ack: UInt32,
                       flags: UInt8, window: UInt16,
                       payload: Data = Data()) -> Data? {
    guard let srcBytes = parseIPv6Address(srcIP),
          let dstBytes = parseIPv6Address(dstIP) else { return nil }
    guard payload.count <= 65495 else { return nil }

    let tcpLen   = UInt16(20 + payload.count)
    let totalLen = 40 + Int(tcpLen)

    var pkt = [UInt8](repeating: 0, count: totalLen)

    // IPv6 header
    pkt[ 0] = 0x60                          // version=6, TC=0, flow label=0
    pkt[ 4] = UInt8(tcpLen >> 8)
    pkt[ 5] = UInt8(tcpLen & 0xFF)
    pkt[ 6] = 6                             // next header: TCP
    pkt[ 7] = 64                            // hop limit
    for i in 0..<16 { pkt[ 8 + i] = srcBytes[i] }
    for i in 0..<16 { pkt[24 + i] = dstBytes[i] }

    // TCP header (checksum calculated below)
    pkt[40] = UInt8(srcPort >> 8); pkt[41] = UInt8(srcPort & 0xFF)
    pkt[42] = UInt8(dstPort >> 8); pkt[43] = UInt8(dstPort & 0xFF)
    pkt[44] = UInt8(seq >> 24);    pkt[45] = UInt8((seq >> 16) & 0xFF)
    pkt[46] = UInt8((seq >> 8) & 0xFF); pkt[47] = UInt8(seq & 0xFF)
    pkt[48] = UInt8(ack >> 24);    pkt[49] = UInt8((ack >> 16) & 0xFF)
    pkt[50] = UInt8((ack >> 8) & 0xFF); pkt[51] = UInt8(ack & 0xFF)
    pkt[52] = 0x50                          // data offset = 5 (20 bytes)
    pkt[53] = flags
    pkt[54] = UInt8(window >> 8); pkt[55] = UInt8(window & 0xFF)

    for (i, b) in payload.enumerated() { pkt[60 + i] = b }

    // TCP checksum: IPv6 pseudo-header + TCP segment
    var pseudo = [UInt8]()
    pseudo.reserveCapacity(40 + Int(tcpLen))
    pseudo.append(contentsOf: srcBytes)         // src IP (16 B)
    pseudo.append(contentsOf: dstBytes)         // dst IP (16 B)
    let tcpLen32 = UInt32(tcpLen)
    pseudo.append(UInt8(tcpLen32 >> 24))
    pseudo.append(UInt8((tcpLen32 >> 16) & 0xFF))
    pseudo.append(UInt8((tcpLen32 >>  8) & 0xFF))
    pseudo.append(UInt8( tcpLen32        & 0xFF))
    pseudo.append(0); pseudo.append(0); pseudo.append(0)
    pseudo.append(6)                            // next header: TCP
    pseudo.append(contentsOf: pkt[40...])       // TCP header + payload

    let ck = onesComplementChecksum(pseudo, start: 0, count: pseudo.count)
    pkt[56] = UInt8(ck >> 8)
    pkt[57] = UInt8(ck & 0xFF)

    return Data(pkt)
}

// Builds a raw IPv6+UDP packet suitable for writing back into packetFlow.
func buildIPv6UDPReply(srcIP: String, srcPort: UInt16,
                       dstIP: String, dstPort: UInt16,
                       payload: Data) -> Data? {
    guard let srcBytes = parseIPv6Address(srcIP),
          let dstBytes = parseIPv6Address(dstIP) else { return nil }
    guard payload.count <= 65527 else { return nil }

    let udpLen   = UInt16(8 + payload.count)
    let totalLen = 40 + Int(udpLen)

    var pkt = [UInt8](repeating: 0, count: totalLen)

    // IPv6 header
    pkt[ 0] = 0x60                          // version=6, TC=0, flow label=0
    pkt[ 4] = UInt8(udpLen >> 8)
    pkt[ 5] = UInt8(udpLen & 0xFF)
    pkt[ 6] = 17                            // next header: UDP
    pkt[ 7] = 64                            // hop limit
    for i in 0..<16 { pkt[ 8 + i] = srcBytes[i] }
    for i in 0..<16 { pkt[24 + i] = dstBytes[i] }

    // UDP header (checksum calculated below)
    pkt[40] = UInt8(srcPort >> 8); pkt[41] = UInt8(srcPort & 0xFF)
    pkt[42] = UInt8(dstPort >> 8); pkt[43] = UInt8(dstPort & 0xFF)
    pkt[44] = UInt8(udpLen >> 8);  pkt[45] = UInt8(udpLen & 0xFF)

    // UDP payload
    for (i, byte) in payload.enumerated() { pkt[48 + i] = byte }

    // UDP checksum: IPv6 pseudo-header + UDP segment
    var pseudo = [UInt8]()
    pseudo.reserveCapacity(40 + Int(udpLen))
    pseudo.append(contentsOf: srcBytes)         // src IP (16 B)
    pseudo.append(contentsOf: dstBytes)         // dst IP (16 B)
    let udpLen32 = UInt32(udpLen)
    pseudo.append(UInt8(udpLen32 >> 24))
    pseudo.append(UInt8((udpLen32 >> 16) & 0xFF))
    pseudo.append(UInt8((udpLen32 >>  8) & 0xFF))
    pseudo.append(UInt8( udpLen32        & 0xFF))
    pseudo.append(0); pseudo.append(0); pseudo.append(0)
    pseudo.append(17)                           // next header: UDP
    pseudo.append(contentsOf: pkt[40...])       // UDP header + payload

    let ck = onesComplementChecksum(pseudo, start: 0, count: pseudo.count)
    pkt[46] = UInt8(ck >> 8)
    pkt[47] = UInt8(ck & 0xFF)

    return Data(pkt)
}

// Parses an IPv6 address in the 8-group hex form produced by formatIPv6() into 16 bytes.
func parseIPv6Address(_ s: String) -> [UInt8]? {
    let groups = s.split(separator: ":", omittingEmptySubsequences: false)
    guard groups.count == 8 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(16)
    for g in groups {
        guard let val = UInt16(g, radix: 16) else { return nil }
        bytes.append(UInt8(val >> 8))
        bytes.append(UInt8(val & 0xFF))
    }
    return bytes
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
