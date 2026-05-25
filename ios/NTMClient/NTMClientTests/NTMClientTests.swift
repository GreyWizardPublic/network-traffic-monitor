import CryptoKit
import Darwin
import XCTest
@testable import NTMClient

// MARK: - ClientVersion constants

final class ClientVersionTests: XCTestCase {

    // kClientVersion must be 4-component MAJOR.MINOR.PATCH.REVISION (per CLAUDE.md versioning)
    func testClientVersionIsSemanticVersion() {
        let parts = kClientVersion.split(separator: ".")
        XCTAssertEqual(parts.count, 4, "kClientVersion must be MAJOR.MINOR.PATCH.REVISION — got '\(kClientVersion)'")
        for part in parts {
            XCTAssertNotNil(Int(part),
                            "Each version component must be an integer — got '\(part)'")
        }
    }

    // Must match kWireProtoVersion in src/proto_client_server.hpp (currently 2)
    func testWireProtoVersionMatchesSpec() {
        XCTAssertEqual(kWireProtoVersion, 2,
                       "kWireProtoVersion must match src/proto_client_server.hpp")
    }

    // Must match kAlpnNtmWire in src/proto_client_server.hpp
    func testAlpnConstantMatchesSpec() {
        XCTAssertEqual(kAlpnNtmWire, "ntm-wire",
                       "kAlpnNtmWire must match src/proto_client_server.hpp kAlpnNtmWire")
    }
}

// MARK: - ServerConfig (NTMClient)

final class NTMClientServerConfigTests: XCTestCase {

    func testDefaultIsNotConfigured() {
        XCTAssertFalse(ServerConfig.default.isConfigured)
    }

    func testIsConfiguredTrueWithURL() {
        XCTAssertTrue(makeConfig(serverURL: "https://ntm.home.me:8443").isConfigured)
    }

    func testIsConfiguredFalseWithEmptyURL() {
        XCTAssertFalse(makeConfig(serverURL: "").isConfigured)
    }

    func testHttpsBaseURLConstruction() {
        let cfg = makeConfig(serverURL: "https://ntm.home.me:9443")
        XCTAssertEqual(cfg.httpsBaseURL?.absoluteString, "https://ntm.home.me:9443")
    }

    func testHttpsBaseURLPrependsHTTPS() {
        let cfg = makeConfig(serverURL: "ntm.home.me:8443")
        XCTAssertEqual(cfg.httpsBaseURL?.absoluteString, "https://ntm.home.me:8443")
    }

    func testHttpsBaseURLNilWhenEmpty() {
        XCTAssertNil(ServerConfig.default.httpsBaseURL)
    }

    func testWireHostExtracted() {
        let cfg = makeConfig(serverURL: "https://ntm.home.me:8443")
        XCTAssertEqual(cfg.wireHost, "ntm.home.me")
    }

    func testDefaultWirePort() {
        XCTAssertEqual(ServerConfig.default.wirePort, 5555)
    }

    func testDefaultNicknameIsEmpty() {
        XCTAssertEqual(ServerConfig.default.nickname, "")
    }

    func testCodableRoundTrip() throws {
        let original = makeConfig(serverURL: "https://ntm.home.me:8443",
                                  wirePort: 5555, nickname: "my-iphone",
                                  cert: Data([0x01, 0x02, 0x03]))
        let data    = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ServerConfig.self, from: data)
        XCTAssertEqual(decoded.serverURL, "https://ntm.home.me:8443")
        XCTAssertEqual(decoded.wirePort, 5555)
        XCTAssertEqual(decoded.nickname, "my-iphone")
        XCTAssertEqual(decoded.pinnedCertData, Data([0x01, 0x02, 0x03]))
    }

    func testCodableRoundTripNilCert() throws {
        let original = makeConfig(serverURL: "https://ntm.home.me:8443")
        let data    = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ServerConfig.self, from: data)
        XCTAssertNil(decoded.pinnedCertData)
    }

    func testLegacyMigrationFromHostAndHttpsPort() throws {
        // Simulate an old 1.2.x UserDefaults payload that used host + httpsPort keys.
        let legacyJSON = """
        {"host":"ntm.home.me","httpsPort":9443,"wirePort":5555,"nickname":"old-iphone"}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ServerConfig.self, from: legacyJSON)
        XCTAssertEqual(decoded.serverURL, "https://ntm.home.me:9443")
        XCTAssertEqual(decoded.wirePort, 5555)
        XCTAssertEqual(decoded.nickname, "old-iphone")
        XCTAssertEqual(decoded.httpsBaseURL?.host, "ntm.home.me")
    }

    // MARK: - Helpers
    private func makeConfig(serverURL: String = "https://ntm.home.me:8443",
                             wirePort: Int = 5555, nickname: String = "",
                             cert: Data? = nil) -> ServerConfig {
        ServerConfig(serverURL: serverURL, wirePort: wirePort,
                     pinnedCertData: cert, nickname: nickname, useWebSocket: false)
    }
}

// MARK: - WireKeyService (Keychain)

final class WireKeyServiceTests: XCTestCase {

    /// Keychain access requires code-signed entitlements that are absent when
    /// `xcodebuild test` runs with CODE_SIGNING_ALLOWED=NO (typical CI / simulator
    /// invocations).  Rather than produce misleading failures we probe on every
    /// test entry and skip the whole suite when the Keychain is inaccessible.
    override func setUpWithError() throws {
        try super.setUpWithError()
        WireKeyService.deleteKey()  // guarantee clean state

        // Probe: try to write one item and immediately delete it.
        let probeQuery: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      "com.ntm.test.keychain.probe",
            kSecAttrAccount:      "probe",
            kSecValueData:        Data([0x01]),
            kSecAttrAccessible:   kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemAdd(probeQuery as CFDictionary, nil)
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: "com.ntm.test.keychain.probe",
                       kSecAttrAccount: "probe"] as CFDictionary)

        try XCTSkipIf(
            status != errSecSuccess && status != errSecDuplicateItem,
            "Keychain unavailable in this environment (OSStatus \(status)) — "
                + "run on a code-signed target or a real device to exercise WireKeyService"
        )
    }

    override func tearDown() {
        WireKeyService.deleteKey()  // leave no test data behind
        super.tearDown()
    }

    func testHasKeyFalseInitially() {
        XCTAssertFalse(WireKeyService.hasKey)
    }

    func testGenerateKeySetsHasKeyTrue() {
        WireKeyService.generateKey()
        XCTAssertTrue(WireKeyService.hasKey)
    }

    func testDeleteKeyClearsHasKey() {
        WireKeyService.generateKey()
        WireKeyService.deleteKey()
        XCTAssertFalse(WireKeyService.hasKey)
    }

    func testLoadPrivateKeyMatchesGenerated() {
        let key    = WireKeyService.generateKey()
        let loaded = WireKeyService.loadPrivateKey()
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded?.rawRepresentation, key.rawRepresentation)
    }

    func testLoadPrivateKeyNilWhenNoKey() {
        XCTAssertNil(WireKeyService.loadPrivateKey())
    }

    func testPublicKeyHexNilWhenNoKey() {
        XCTAssertNil(WireKeyService.publicKeyHex())
    }

    func testPublicKeyHexIsExactly64Chars() {
        WireKeyService.generateKey()
        XCTAssertEqual(WireKeyService.publicKeyHex()?.count, 64)
    }

    func testPublicKeyHexIsLowercaseHexOnly() {
        WireKeyService.generateKey()
        guard let hex = WireKeyService.publicKeyHex() else {
            return XCTFail("publicKeyHex() returned nil after generateKey()")
        }
        XCTAssertTrue(hex.allSatisfy(\.isHexDigit), "Must be hex — got: \(hex)")
        XCTAssertEqual(hex, hex.lowercased(), "Must be lowercase — got: \(hex)")
    }

    func testPublicKeyHexMatchesPrivateKeyPublicKey() {
        let key         = WireKeyService.generateKey()
        let expectedHex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(WireKeyService.publicKeyHex(), expectedHex)
    }

    func testGenerateKeyOverwritesPreviousKey() {
        let key1 = WireKeyService.generateKey()
        let key2 = WireKeyService.generateKey()
        // New key pair — raw bytes must differ
        XCTAssertNotEqual(key1.rawRepresentation, key2.rawRepresentation)
        // Stored key is the second one
        XCTAssertEqual(WireKeyService.loadPrivateKey()?.rawRepresentation,
                       key2.rawRepresentation)
    }

    // Wire-protocol auth: Ed25519 sign(prefix ‖ nonce) → verify with stored public key
    func testKeyCanSignAndServerCanVerify() throws {
        let key     = WireKeyService.generateKey()
        let message = Data("NTM-AUTH-v2".utf8) + Data(repeating: 0xAB, count: 32)
        let sig     = try key.signature(for: message)
        XCTAssertTrue(key.publicKey.isValidSignature(sig, for: message),
                      "Server-side verification of auth signature must succeed")
    }

    // Signature is not transferable to a different key pair
    func testSignatureDoesNotVerifyWithDifferentKey() throws {
        let key1    = WireKeyService.generateKey()
        let key2    = Curve25519.Signing.PrivateKey()
        let message = Data("NTM-AUTH-v2".utf8) + Data(repeating: 0xFF, count: 32)
        let sig     = try key1.signature(for: message)
        XCTAssertFalse(key2.publicKey.isValidSignature(sig, for: message))
    }
}

// MARK: - IPPacket parsing (IPPacket.swift moved to Shared/)

final class IPPacketParseTests: XCTestCase {

    // MARK: IPv4 TCP

    func testParseIPv4TCPSYNPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "192.168.1.1", srcPort: 54321,
                             dstIP: "8.8.8.8",     dstPort: 443,
                             seq: 1000, ack: 0, flags: 0x02 /*SYN*/, window: 65535))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))

        XCTAssertEqual(p.version, 4)
        XCTAssertEqual(p.proto, 6)              // TCP
        XCTAssertEqual(p.srcIP, "192.168.1.1")
        XCTAssertEqual(p.dstIP, "8.8.8.8")
        XCTAssertEqual(p.totalBytes, pkt.count)
        XCTAssertEqual(p.ihlBytes, 20)          // no IP options
        XCTAssertEqual(p.srcPort, 0)            // TCP: port fields unused
        XCTAssertEqual(p.dstPort, 0)
        XCTAssertTrue(p.udpPayloadRange.isEmpty)
    }

    func testParseIPv4TCPWithPayload() throws {
        let payload = Data("GET / HTTP/1.0\r\n\r\n".utf8)
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 50000,
                             dstIP: "93.184.216.34", dstPort: 80,
                             seq: 1, ack: 1, flags: 0x18 /*PSH+ACK*/, window: 8192,
                             payload: payload))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertEqual(p.totalBytes, pkt.count)
        XCTAssertEqual(p.proto, 6)
    }

    // MARK: IPv4 UDP

    func testParseIPv4UDPExtractsPorts() throws {
        let payload = Data("hello".utf8)
        let pkt = try XCTUnwrap(
            buildIPv4UDPReply(srcIP: "8.8.8.8",      srcPort: 53,
                              dstIP: "192.168.1.2",   dstPort: 55555,
                              payload: payload))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))

        XCTAssertEqual(p.version, 4)
        XCTAssertEqual(p.proto, 17)             // UDP
        XCTAssertEqual(p.srcIP, "8.8.8.8")
        XCTAssertEqual(p.dstIP, "192.168.1.2")
        XCTAssertEqual(p.srcPort, 53)
        XCTAssertEqual(p.dstPort, 55555)
        XCTAssertFalse(p.udpPayloadRange.isEmpty)
        XCTAssertEqual(p.udpPayload(in: pkt), payload)
    }

    func testParseIPv4UDPEmptyPayloadYieldsNilPayload() throws {
        let pkt = try XCTUnwrap(
            buildIPv4UDPReply(srcIP: "1.1.1.1", srcPort: 53,
                              dstIP: "192.168.0.1", dstPort: 5353,
                              payload: Data()))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertNil(p.udpPayload(in: pkt),
                     "Empty UDP payload should yield nil, not empty Data")
    }

    // MARK: IPv4 rejection cases

    func testParseIPv4TooShortReturnsNil() {
        XCTAssertNil(IPPacket.parse(Data(count: 19), af: AF_INET))
    }

    func testParseIPv4WrongVersionReturnsNil() {
        var b = [UInt8](repeating: 0, count: 20)
        b[0] = 0x60     // version = 6 (IPv6)
        XCTAssertNil(IPPacket.parse(Data(b), af: AF_INET))
    }

    func testParseIPv4IHLTooSmallReturnsNil() {
        var b = [UInt8](repeating: 0, count: 20)
        b[0] = 0x44     // version = 4, IHL = 4 (< 5 — invalid)
        XCTAssertNil(IPPacket.parse(Data(b), af: AF_INET))
    }

    func testParseUnknownAddressFamilyReturnsNil() {
        XCTAssertNil(IPPacket.parse(Data(count: 40), af: 0))
        XCTAssertNil(IPPacket.parse(Data(count: 40), af: 255))
    }

    // MARK: D-line format

    func testDLineFormat() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 1234,
                             dstIP: "93.184.216.34", dstPort: 80,
                             seq: 0, ack: 0, flags: 0x02, window: 8192))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        // Wire protocol: "D utun {srcIP} {dstIP} {bytes}"
        XCTAssertEqual(p.dLine, "D utun 10.0.0.1 93.184.216.34 \(pkt.count)")
    }

    func testDLineContainsNoNewlines() throws {
        let pkt = try XCTUnwrap(
            buildIPv4UDPReply(srcIP: "1.2.3.4", srcPort: 53,
                              dstIP: "5.6.7.8", dstPort: 12345,
                              payload: Data([0x00])))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertFalse(p.dLine.contains("\n"), "D-line must not contain a newline")
        XCTAssertFalse(p.dLine.contains("\r"), "D-line must not contain a carriage return")
    }

    // MARK: IPv6 TCP

    func testParseIPv6TCPPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv6Packet(srcIP: "2001:db8:0:0:0:0:0:1",          srcPort: 54321,
                             dstIP: "2001:4860:4860:0:0:0:0:8888",   dstPort: 443,
                             seq: 42, ack: 0, flags: 0x02, window: 65535))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET6))

        XCTAssertEqual(p.version, 6)
        XCTAssertEqual(p.proto, 6)      // TCP
        XCTAssertEqual(p.srcIP, "2001:db8:0:0:0:0:0:1")
        XCTAssertEqual(p.dstIP, "2001:4860:4860:0:0:0:0:8888")
        XCTAssertEqual(p.totalBytes, pkt.count)
        XCTAssertEqual(p.ihlBytes, 0)   // IPv6 has no IHL field
    }

    // MARK: IPv6 UDP

    func testParseIPv6UDPExtractsPorts() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let pkt = try XCTUnwrap(
            buildIPv6UDPReply(srcIP: "2001:db8:0:0:0:0:0:1", srcPort: 53,
                              dstIP: "fe80:0:0:0:0:0:0:1",   dstPort: 60000,
                              payload: payload))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET6))

        XCTAssertEqual(p.proto, 17)
        XCTAssertEqual(p.srcPort, 53)
        XCTAssertEqual(p.dstPort, 60000)
        XCTAssertEqual(p.udpPayload(in: pkt), payload)
    }

    // MARK: IPv6 rejection cases

    func testParseIPv6TooShortReturnsNil() {
        XCTAssertNil(IPPacket.parse(Data(count: 39), af: AF_INET6))
    }

    func testParseIPv6WrongVersionReturnsNil() {
        var b = [UInt8](repeating: 0, count: 40)
        b[0] = 0x40     // version = 4 (IPv4)
        XCTAssertNil(IPPacket.parse(Data(b), af: AF_INET6))
    }

    // MARK: UDP payload

    func testUdpPayloadNilForTCPPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "1.2.3.4", srcPort: 80,
                             dstIP: "5.6.7.8", dstPort: 12345,
                             seq: 0, ack: 0, flags: 0x10, window: 1024))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertNil(p.udpPayload(in: pkt), "TCP packets have no UDP payload")
    }
}

// MARK: - TCPHeader parsing

final class TCPHeaderTests: XCTestCase {

    func testParseTCPSYNPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "192.168.1.1", srcPort: 9999,
                             dstIP: "1.2.3.4",     dstPort: 80,
                             seq: 0xDEADBEEF, ack: 0,
                             flags: 0x02 /*SYN*/, window: 8192))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertEqual(tcp.srcPort, 9999)
        XCTAssertEqual(tcp.dstPort, 80)
        XCTAssertEqual(tcp.seq, 0xDEADBEEF)
        XCTAssertEqual(tcp.ack, 0)
        XCTAssertEqual(tcp.headerBytes, 20)
        XCTAssertEqual(tcp.window, 8192)
        XCTAssertTrue(tcp.isSYN)
        XCTAssertFalse(tcp.isACK)
        XCTAssertFalse(tcp.isFIN)
        XCTAssertFalse(tcp.isRST)
    }

    func testParseTCPACKPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 443,
                             dstIP: "10.0.0.2", dstPort: 55000,
                             seq: 1, ack: 1,
                             flags: 0x10 /*ACK*/, window: 65535))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertFalse(tcp.isSYN)
        XCTAssertTrue(tcp.isACK)
        XCTAssertFalse(tcp.isFIN)
        XCTAssertFalse(tcp.isRST)
    }

    func testParseTCPFINACKPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 443,
                             dstIP: "10.0.0.2", dstPort: 55000,
                             seq: 100, ack: 200,
                             flags: 0x11 /*FIN+ACK*/, window: 512))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertTrue(tcp.isFIN)
        XCTAssertTrue(tcp.isACK)
        XCTAssertFalse(tcp.isSYN)
        XCTAssertFalse(tcp.isRST)
    }

    func testParseTCPRSTPacket() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 443,
                             dstIP: "10.0.0.2", dstPort: 55000,
                             seq: 0, ack: 0,
                             flags: 0x04 /*RST*/, window: 0))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertTrue(tcp.isRST)
        XCTAssertFalse(tcp.isSYN)
        XCTAssertFalse(tcp.isACK)
        XCTAssertFalse(tcp.isFIN)
    }

    func testParseTCPWithPayload() throws {
        let payload = Data("GET / HTTP/1.0\r\n\r\n".utf8)
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "10.0.0.1", srcPort: 54321,
                             dstIP: "93.184.216.34", dstPort: 80,
                             seq: 1, ack: 1,
                             flags: 0x18 /*PSH+ACK*/, window: 8192,
                             payload: payload))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertEqual(tcp.payloadLen, payload.count)
        XCTAssertEqual(Data(pkt[tcp.payloadRange]), payload)
    }

    func testParseTCPNilForUDPPacket() throws {
        let pkt = try XCTUnwrap(
            buildIPv4UDPReply(srcIP: "8.8.8.8", srcPort: 53,
                              dstIP: "192.168.0.1", dstPort: 5353,
                              payload: Data([0x00, 0x01])))
        let ip = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertNil(ip.parseTCP(in: pkt), "parseTCP must return nil for UDP packets")
    }

    func testParseTCPFromIPv6Packet() throws {
        let pkt = try XCTUnwrap(
            buildTCPv6Packet(srcIP: "2001:db8:0:0:0:0:0:1", srcPort: 12345,
                             dstIP: "2001:db8:0:0:0:0:0:2", dstPort: 443,
                             seq: 77, ack: 88, flags: 0x02, window: 32768))
        let ip  = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET6))
        let tcp = try XCTUnwrap(ip.parseTCP(in: pkt))

        XCTAssertEqual(tcp.srcPort, 12345)
        XCTAssertEqual(tcp.dstPort, 443)
        XCTAssertEqual(tcp.seq, 77)
        XCTAssertEqual(tcp.ack, 88)
        XCTAssertTrue(tcp.isSYN)
    }
}

// MARK: - Packet builder edge cases

final class PacketBuilderTests: XCTestCase {

    func testBuildTCPv4InvalidSourceIPReturnsNil() {
        XCTAssertNil(buildTCPv4Packet(srcIP: "not.an.ip", srcPort: 80,
                                       dstIP: "1.2.3.4", dstPort: 80,
                                       seq: 0, ack: 0, flags: 0, window: 0))
    }

    func testBuildTCPv4InvalidDestIPReturnsNil() {
        XCTAssertNil(buildTCPv4Packet(srcIP: "1.2.3.4", srcPort: 80,
                                       dstIP: "badaddr", dstPort: 80,
                                       seq: 0, ack: 0, flags: 0, window: 0))
    }

    func testBuildIPv4UDPInvalidSrcIPReturnsNil() {
        XCTAssertNil(buildIPv4UDPReply(srcIP: "::::", srcPort: 53,
                                        dstIP: "1.2.3.4", dstPort: 5353,
                                        payload: Data()))
    }

    func testBuildTCPv6InvalidIPReturnsNil() {
        // parseIPv6Address requires exactly 8 groups — compressed notation not supported
        XCTAssertNil(buildTCPv6Packet(srcIP: "::1", srcPort: 80,
                                       dstIP: "::2", dstPort: 443,
                                       seq: 0, ack: 0, flags: 0, window: 0))
    }

    // Round-trip: build → parse → same IP / protocol fields
    func testTCPv4RoundTrip() throws {
        let pkt = try XCTUnwrap(
            buildTCPv4Packet(srcIP: "172.16.0.1", srcPort: 8080,
                             dstIP: "172.16.0.2", dstPort: 443,
                             seq: 0xABCDEF00, ack: 0x12345678,
                             flags: 0x18, window: 16384,
                             payload: Data([0xCA, 0xFE])))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertEqual(p.srcIP, "172.16.0.1")
        XCTAssertEqual(p.dstIP, "172.16.0.2")
        XCTAssertEqual(p.proto, 6)
        XCTAssertEqual(p.totalBytes, pkt.count)
    }

    func testUDPv4RoundTrip() throws {
        let payload = Data(repeating: 0xAA, count: 100)
        let pkt = try XCTUnwrap(
            buildIPv4UDPReply(srcIP: "10.10.10.1", srcPort: 5353,
                              dstIP: "10.10.10.2", dstPort: 55555,
                              payload: payload))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET))
        XCTAssertEqual(p.proto, 17)
        XCTAssertEqual(p.srcPort, 5353)
        XCTAssertEqual(p.dstPort, 55555)
        XCTAssertEqual(p.udpPayload(in: pkt), payload)
    }

    func testTCPv6RoundTrip() throws {
        let pkt = try XCTUnwrap(
            buildTCPv6Packet(srcIP: "2001:db8:0:0:0:0:0:1", srcPort: 9999,
                             dstIP: "2001:db8:0:0:0:0:0:2", dstPort: 443,
                             seq: 11, ack: 22, flags: 0x02, window: 4096))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET6))
        XCTAssertEqual(p.srcIP, "2001:db8:0:0:0:0:0:1")
        XCTAssertEqual(p.dstIP, "2001:db8:0:0:0:0:0:2")
        XCTAssertEqual(p.proto, 6)
    }

    func testUDPv6RoundTrip() throws {
        let payload = Data([0x01, 0x02, 0x03, 0x04])
        let pkt = try XCTUnwrap(
            buildIPv6UDPReply(srcIP: "2001:db8:0:0:0:0:0:1", srcPort: 53,
                              dstIP: "fe80:0:0:0:0:0:0:1",   dstPort: 60000,
                              payload: payload))
        let p = try XCTUnwrap(IPPacket.parse(pkt, af: AF_INET6))
        XCTAssertEqual(p.proto, 17)
        XCTAssertEqual(p.srcPort, 53)
        XCTAssertEqual(p.dstPort, 60000)
        XCTAssertEqual(p.udpPayload(in: pkt), payload)
    }
}

// MARK: - parseIPv6Address helper

final class ParseIPv6AddressTests: XCTestCase {

    func testValidFullAddress() {
        let bytes = parseIPv6Address("2001:db8:0:0:0:0:0:1")
        XCTAssertEqual(bytes?.count, 16)
        XCTAssertEqual(bytes?[0],  0x20)
        XCTAssertEqual(bytes?[1],  0x01)
        XCTAssertEqual(bytes?[2],  0x0D)
        XCTAssertEqual(bytes?[3],  0xB8)
        XCTAssertEqual(bytes?[15], 0x01)
    }

    func testLocalhostAddress() {
        guard let bytes = parseIPv6Address("0:0:0:0:0:0:0:1") else {
            return XCTFail("parseIPv6Address must succeed for loopback")
        }
        XCTAssertEqual(bytes.count, 16)
        XCTAssertEqual(bytes[15], 0x01)
        // All preceding bytes are zero
        XCTAssertTrue(bytes.dropLast().allSatisfy { $0 == 0 })
    }

    func testAllZeroesAddress() {
        let bytes = parseIPv6Address("0:0:0:0:0:0:0:0")
        XCTAssertEqual(bytes?.count, 16)
        XCTAssertTrue(bytes?.allSatisfy { $0 == 0 } ?? false)
    }

    func testInvalidGroupCountReturnsNil() {
        // Compressed notation is not supported — must supply all 8 groups
        XCTAssertNil(parseIPv6Address("::1"))
        XCTAssertNil(parseIPv6Address("2001:db8::1"))
        XCTAssertNil(parseIPv6Address("2001:db8:0:0:0:0:1"))   // only 7 groups
    }

    func testNonHexGroupReturnsNil() {
        XCTAssertNil(parseIPv6Address("ZZZZ:0:0:0:0:0:0:1"))
    }

    func testEmptyStringReturnsNil() {
        XCTAssertNil(parseIPv6Address(""))
    }
}

// MARK: - FlowAggregator

final class FlowAggregatorTests: XCTestCase {

    private func makePacket(src: String, dst: String, bytes: Int) -> IPPacket {
        // Build a minimal IPv4 TCP packet and then construct IPPacket directly.
        // We can't call the private init, so build a real packet and parse it.
        let pkt = buildTCPv4Packet(srcIP: src, srcPort: 1234, dstIP: dst, dstPort: 80,
                                    seq: 0, ack: 0, flags: 0x10, window: 1024)!
        // Parse gives us totalBytes == pkt.count; pad to hit the requested byte count
        // by building a packet with a payload of (bytes - 40) zeros.
        let payload = Data(repeating: 0, count: max(0, bytes - 40))
        let padded = buildTCPv4Packet(srcIP: src, srcPort: 1234, dstIP: dst, dstPort: 80,
                                       seq: 0, ack: 0, flags: 0x10, window: 1024,
                                       payload: payload)!
        return IPPacket.parse(padded, af: AF_INET)!
    }

    func testEmptyDrainReturnsNoLines() {
        let agg = FlowAggregator()
        let (lines, count) = agg.drain()
        XCTAssertTrue(lines.isEmpty)
        XCTAssertEqual(count, 0)
    }

    func testSingleFlowProducesOneLine() {
        let agg = FlowAggregator()
        agg.observe(makePacket(src: "10.0.0.1", dst: "8.8.8.8", bytes: 100))
        let (lines, count) = agg.drain()
        XCTAssertEqual(count, 1)
        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(lines[0].hasPrefix("D utun 10.0.0.1 8.8.8.8 "),
                      "D-line format mismatch: \(lines[0])")
    }

    func testSameTupleAccumulatesBytes() {
        let agg = FlowAggregator()
        let p1 = makePacket(src: "10.0.0.1", dst: "8.8.8.8", bytes: 60)
        let p2 = makePacket(src: "10.0.0.1", dst: "8.8.8.8", bytes: 100)
        agg.observe(p1)
        agg.observe(p2)
        let (lines, count) = agg.drain()
        XCTAssertEqual(count, 1)
        // bytes field is the 5th token
        let bytes = lines[0].split(separator: " ").last.flatMap { UInt64($0) }
        XCTAssertEqual(bytes, UInt64(p1.totalBytes + p2.totalBytes))
    }

    func testDistinctTuplesProduceSeparateLines() {
        let agg = FlowAggregator()
        agg.observe(makePacket(src: "10.0.0.1", dst: "8.8.8.8", bytes: 60))
        agg.observe(makePacket(src: "10.0.0.2", dst: "8.8.8.8", bytes: 60))
        let (lines, count) = agg.drain()
        XCTAssertEqual(count, 2)
        XCTAssertEqual(lines.count, 2)
    }

    func testDrainResetsAccumulator() {
        let agg = FlowAggregator()
        agg.observe(makePacket(src: "10.0.0.1", dst: "8.8.8.8", bytes: 60))
        _ = agg.drain()
        let (lines, count) = agg.drain()
        XCTAssertTrue(lines.isEmpty)
        XCTAssertEqual(count, 0)
    }

    func testReverseDirectionIsSeparateFlow() {
        let agg = FlowAggregator()
        agg.observe(makePacket(src: "1.2.3.4", dst: "5.6.7.8", bytes: 60))
        agg.observe(makePacket(src: "5.6.7.8", dst: "1.2.3.4", bytes: 60))
        let (_, count) = agg.drain()
        XCTAssertEqual(count, 2, "src→dst and dst→src are distinct flows")
    }
}
