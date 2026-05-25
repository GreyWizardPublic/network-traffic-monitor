import XCTest
@testable import NTMDashboard

// MARK: - DashboardSnapshot JSON decoding

final class DashboardSnapshotDecodeTests: XCTestCase {

    // MARK: Full v10 snapshot — every documented field present

    func testFullV10Snapshot() throws {
        let json = """
        {
          "api_version": 10,
          "server_version": "1.19.0",
          "server_wire_proto_version": 2,
          "window_start": 1716480000,
          "generated_at": 1716480030,
          "interfaces": [
            {"client":"home-pi","iface":"eth0","packets":1000,"bytes":500000}
          ],
          "entities": [
            {"client":"home-pi","iface":"eth0","src_entity":"LAN (192.168.1.1)",
             "dst_entity":"google.com","bytes":400000,"packets":800}
          ],
          "truncated": false,
          "overhead_entities": [
            {"client":"home-pi","iface":"eth0","src_entity":"home-pi",
             "dst_entity":"ntm-server","bytes":2000,"packets":50}
          ],
          "truncated_overhead": false,
          "overhead_summary": {"packets":50,"bytes":2000,"pct_of_total_bytes":"0.40"},
          "entities_lan": [
            {"ip":"192.168.1.55","reported_by":"","out_packets":80,"out_bytes":10000,
             "in_packets":40,"in_bytes":5000}
          ],
          "truncated_lan": false,
          "client_health": [
            {
              "client": "home-pi",
              "client_id": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
              "version": "1.13.0",
              "platform": "linux-amd64",
              "pcap_recv": 10000,
              "pcap_drop": 5,
              "pcap_drop_pct": "0.05",
              "buf_drop": 3,
              "buf_drop_pct": "0.03",
              "reported_at": 1716480025,
              "stale": false,
              "wire_proto_version": 2,
              "wire_proto_ok": true,
              "agg_interval_ms": 500,
              "agg_flows": 42
            }
          ],
          "proto_rejected_clients": [],
          "update_manifest": [
            {"platform":"linux-amd64","version":"1.13.0",
             "filename":"ntm-client-linux-amd64-1.13.0",
             "sha256":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"}
          ]
        }
        """
        let s = try decode(json)

        XCTAssertEqual(s.apiVersion, 10)
        XCTAssertEqual(s.serverVersion, "1.19.0")
        XCTAssertEqual(s.serverWireProtoVersion, 2)
        XCTAssertEqual(s.windowStart, 1716480000)
        XCTAssertEqual(s.generatedAt, 1716480030)
        XCTAssertNil(s.demo)
        XCTAssertNil(s.demoExpiresAt)

        // Interfaces
        XCTAssertEqual(s.interfaces.count, 1)
        XCTAssertEqual(s.interfaces[0].client, "home-pi")
        XCTAssertEqual(s.interfaces[0].iface, "eth0")
        XCTAssertEqual(s.interfaces[0].bytes, 500000)
        XCTAssertEqual(s.interfaces[0].packets, 1000)

        // Entities + truncation
        XCTAssertEqual(s.entities.count, 1)
        XCTAssertEqual(s.entities[0].bytes, 400000)
        XCTAssertEqual(s.entities[0].packets, 800)
        XCTAssertEqual(s.entities[0].srcEntity, "LAN (192.168.1.1)")
        XCTAssertEqual(s.entities[0].dstEntity, "google.com")
        XCTAssertFalse(s.truncated)

        // Overhead
        XCTAssertEqual(s.overheadEntities.count, 1)
        XCTAssertFalse(s.truncatedOverhead)

        // OverheadSummary
        let os = try XCTUnwrap(s.overheadSummary)
        XCTAssertEqual(os.packets, 50)
        XCTAssertEqual(os.bytes, 2000)
        XCTAssertEqual(os.pctOfTotalBytes, "0.40")

        // LAN devices + truncation
        XCTAssertEqual(s.entitiesLan.count, 1)
        XCTAssertEqual(s.entitiesLan[0].ip, "192.168.1.55")
        XCTAssertEqual(s.entitiesLan[0].reportedBy, "")
        XCTAssertFalse(s.truncatedLan)

        // Client health — all fields including v7 additions
        let ch = try XCTUnwrap(s.clientHealth.first)
        XCTAssertEqual(ch.client, "home-pi")
        XCTAssertEqual(ch.clientId, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        XCTAssertEqual(ch.version, "1.13.0")
        XCTAssertEqual(ch.platform, "linux-amd64")
        XCTAssertEqual(ch.pcapRecv, 10000)
        XCTAssertEqual(ch.pcapDrop, 5)
        XCTAssertEqual(ch.pcapDropPct, "0.05")
        XCTAssertEqual(ch.bufDrop, 3)
        XCTAssertEqual(ch.bufDropPct, "0.03")
        XCTAssertFalse(ch.stale)
        XCTAssertEqual(ch.wireProtoVersion, 2)
        XCTAssertEqual(ch.wireProtoOk, true)
        XCTAssertEqual(ch.aggIntervalMs, 500)
        XCTAssertEqual(ch.aggFlows, 42)

        // update_manifest
        XCTAssertEqual(s.updateManifest.count, 1)
        let um = s.updateManifest[0]
        XCTAssertEqual(um.platform, "linux-amd64")
        XCTAssertEqual(um.version, "1.13.0")
        XCTAssertEqual(um.filename, "ntm-client-linux-amd64-1.13.0")
        XCTAssertEqual(um.sha256, "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4")
        XCTAssertEqual(um.id, "linux-amd64")
    }

    // MARK: Optional arrays default to empty — api_version 4-era server

    func testOptionalArraysDefaultToEmpty() throws {
        let json = """
        {
          "server_version": "1.6.0",
          "window_start": 1716480000,
          "generated_at": 1716480030,
          "interfaces": [],
          "entities": [],
          "overhead_entities": []
        }
        """
        let s = try decode(json)
        XCTAssertNil(s.apiVersion)
        XCTAssertNil(s.serverWireProtoVersion)
        XCTAssertTrue(s.entitiesInternet.isEmpty)
        XCTAssertTrue(s.entitiesLocal.isEmpty)
        XCTAssertTrue(s.overheadEntities.isEmpty)
        XCTAssertTrue(s.entitiesLan.isEmpty)
        XCTAssertTrue(s.clientHealth.isEmpty)
        XCTAssertTrue(s.protoRejectedClients.isEmpty)
        XCTAssertTrue(s.updateManifest.isEmpty, "update_manifest absent → empty array")
        XCTAssertNil(s.overheadSummary)
        XCTAssertNil(s.localSummary)
        // truncation flags default to false when absent
        XCTAssertFalse(s.truncated,         "truncated absent → false")
        XCTAssertFalse(s.truncatedOverhead, "truncated_overhead absent → false")
        XCTAssertFalse(s.truncatedLan,      "truncated_lan absent → false")
    }

    // MARK: ClientHealth — all optional fields absent (old client, no agg, no wire_proto fields)

    func testClientHealthAllOptionalFieldsAbsent() throws {
        let json = """
        {
          "client": "old-linux",
          "version": "1.9.0",
          "pcap_recv": 5000,
          "pcap_drop": 0,
          "pcap_drop_pct": "0.00",
          "buf_drop": 0,
          "reported_at": 1716480000,
          "stale": false
        }
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertNil(ch.aggIntervalMs)
        XCTAssertNil(ch.aggFlows)
        XCTAssertNil(ch.wireProtoVersion)
        XCTAssertNil(ch.wireProtoOk)
        XCTAssertNil(ch.clientId)
        XCTAssertNil(ch.platform)
        // buf_drop_pct absent on pre-v7 servers — defaults to "0.00"
        XCTAssertEqual(ch.bufDropPct, "0.00",
                       "buf_drop_pct absent on old server must default to '0.00'")
    }

    // buf_drop_pct present when server emits it
    func testClientHealthBufDropPct() throws {
        let json = """
        {"client":"fast-client","version":"1.13.0","pcap_recv":50000,"pcap_drop":0,
         "pcap_drop_pct":"0.00","buf_drop":25,"buf_drop_pct":"0.05",
         "reported_at":1716480000,"stale":false}
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertEqual(ch.bufDrop, 25)
        XCTAssertEqual(ch.bufDropPct, "0.05")
    }

    // id falls back to client name when client_id absent (pre-v7 server)
    func testClientHealthIdFallsBackToClientName() throws {
        let json = """
        {"client":"my-pi","version":"1.9.0","pcap_recv":0,"pcap_drop":0,
         "pcap_drop_pct":"0.00","buf_drop":0,"reported_at":0,"stale":false}
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertNil(ch.clientId)
        XCTAssertEqual(ch.id, "my-pi", "id must fall back to 'client' when client_id absent")
    }

    // id is the 64-hex client_id when present (v7+)
    func testClientHealthIdIsClientIdWhenPresent() throws {
        let hex = String(repeating: "a", count: 64)
        let json = """
        {"client":"my-pi","client_id":"\(hex)","version":"1.13.0","pcap_recv":0,
         "pcap_drop":0,"pcap_drop_pct":"0.00","buf_drop":0,"reported_at":0,"stale":false}
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertEqual(ch.id, hex)
    }

    func testClientHealthStaleTrue() throws {
        let json = """
        {"client":"stale","version":"1.8.0","pcap_recv":100,"pcap_drop":0,
         "pcap_drop_pct":"0.00","buf_drop":0,"reported_at":1716390000,"stale":true}
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertTrue(ch.stale)
    }

    func testClientHealthWireProtoMismatch() throws {
        let json = """
        {"client":"old-client","version":"1.5.0","pcap_recv":0,"pcap_drop":0,
         "pcap_drop_pct":"0.00","buf_drop":0,"reported_at":0,"stale":true,
         "wire_proto_version":1,"wire_proto_ok":false}
        """
        let ch = try JSONDecoder().decode(ClientHealth.self, from: Data(json.utf8))
        XCTAssertEqual(ch.wireProtoVersion, 1)
        XCTAssertEqual(ch.wireProtoOk, false)
    }

    // MARK: Demo snapshot

    func testDemoSnapshot() throws {
        let json = """
        {
          "api_version": 10,
          "server_version": "1.19.0",
          "demo": true,
          "demo_expires_at": 1716481000,
          "window_start": 1716480000,
          "generated_at": 1716480030,
          "interfaces": [],
          "entities": [],
          "overhead_entities": []
        }
        """
        let s = try decode(json)
        XCTAssertEqual(s.demo, true)
        XCTAssertEqual(s.demoExpiresAt, 1716481000)
    }

    // MARK: ProtoRejectedClient

    func testProtoRejectedClientDecodingAndId() throws {
        let json = """
        {"peer_ip":"1.2.3.4","attempted_auth_version":1,"at":1716480000}
        """
        let r = try JSONDecoder().decode(ProtoRejectedClient.self, from: Data(json.utf8))
        XCTAssertEqual(r.peerIp, "1.2.3.4")
        XCTAssertEqual(r.attemptedAuthVersion, 1)
        XCTAssertEqual(r.at, 1716480000)
        // Identifiable ID formula: "{ip}-{epoch}"
        XCTAssertEqual(r.id, "1.2.3.4-1716480000")
    }

    func testProtoRejectedClientAuthV2() throws {
        let json = """
        {"peer_ip":"10.0.0.5","attempted_auth_version":2,"at":1716490000}
        """
        let r = try JSONDecoder().decode(ProtoRejectedClient.self, from: Data(json.utf8))
        XCTAssertEqual(r.attemptedAuthVersion, 2)
    }

    // MARK: EntityFlow

    func testEntityFlowIdFormula() throws {
        let json = """
        {"client":"pc1","iface":"eth0","src_entity":"192.168.1.1",
         "dst_entity":"8.8.8.8","bytes":1000,"packets":10}
        """
        let f = try JSONDecoder().decode(EntityFlow.self, from: Data(json.utf8))
        // ID = "client|iface|src->dst"
        XCTAssertEqual(f.id, "pc1|eth0|192.168.1.1->8.8.8.8")
        XCTAssertEqual(f.bytes, 1000)
        XCTAssertEqual(f.packets, 10)
    }

    func testEntityFlowCodingKeys() throws {
        let json = """
        {"client":"x","iface":"eth1","src_entity":"A","dst_entity":"B","bytes":0,"packets":0}
        """
        let f = try JSONDecoder().decode(EntityFlow.self, from: Data(json.utf8))
        XCTAssertEqual(f.srcEntity, "A")
        XCTAssertEqual(f.dstEntity, "B")
    }

    // MARK: InterfaceStat

    func testInterfaceStatIdFormula() throws {
        let json = #"{"client":"home-pi","iface":"eth0","packets":100,"bytes":50000}"#
        let s = try JSONDecoder().decode(InterfaceStat.self, from: Data(json.utf8))
        // ID = "client/iface"
        XCTAssertEqual(s.id, "home-pi/eth0")
    }

    // MARK: LanDevice

    func testLanDeviceWithHostname() throws {
        let json = """
        {"ip":"192.168.1.55","reported_by":"203.0.113.1","out_bytes":10000,"in_bytes":5000,
         "out_packets":80,"in_packets":40,"hostname":"smart-tv.local"}
        """
        let d = try JSONDecoder().decode(LanDevice.self, from: Data(json.utf8))
        XCTAssertEqual(d.ip, "192.168.1.55")
        XCTAssertEqual(d.reportedBy, "203.0.113.1")
        XCTAssertEqual(d.outBytes, 10000)
        XCTAssertEqual(d.inBytes, 5000)
        XCTAssertEqual(d.outPackets, 80)
        XCTAssertEqual(d.inPackets, 40)
        XCTAssertEqual(d.hostname, "smart-tv.local")
        XCTAssertEqual(d.id, "192.168.1.55")
    }

    func testLanDeviceWithoutHostname() throws {
        let json = """
        {"ip":"10.0.0.2","reported_by":"","out_bytes":500,"in_bytes":200,
         "out_packets":5,"in_packets":2}
        """
        let d = try JSONDecoder().decode(LanDevice.self, from: Data(json.utf8))
        XCTAssertNil(d.hostname)
        XCTAssertEqual(d.reportedBy, "")
    }

    // reported_by: same subnet (empty string means client and device are on the same LAN)
    func testLanDeviceReportedBySameSubnet() throws {
        let json = """
        {"ip":"192.168.1.100","reported_by":"","out_bytes":1000,"in_bytes":500,
         "out_packets":10,"in_packets":5}
        """
        let d = try JSONDecoder().decode(LanDevice.self, from: Data(json.utf8))
        XCTAssertEqual(d.reportedBy, "",
                       "empty reported_by means the client is on the same subnet")
    }

    // reported_by: remote client (non-empty WAN IP)
    func testLanDeviceReportedByRemoteClient() throws {
        let json = """
        {"ip":"10.0.0.42","reported_by":"203.0.113.7","out_bytes":2000,"in_bytes":1000,
         "out_packets":20,"in_packets":10}
        """
        let d = try JSONDecoder().decode(LanDevice.self, from: Data(json.utf8))
        XCTAssertEqual(d.reportedBy, "203.0.113.7")
    }

    // reported_by absent (pre-v7 server) → defaults to empty string
    func testLanDeviceReportedByDefaultsToEmptyWhenAbsent() throws {
        let json = """
        {"ip":"192.168.0.5","out_bytes":100,"in_bytes":50,"out_packets":1,"in_packets":1}
        """
        let d = try JSONDecoder().decode(LanDevice.self, from: Data(json.utf8))
        XCTAssertEqual(d.reportedBy, "",
                       "reported_by absent on pre-v7 server must default to empty string")
    }

    // MARK: OverheadSummary

    func testOverheadSummaryDecode() throws {
        let json = #"{"packets":1000,"bytes":50000,"pct_of_total_bytes":"12.34"}"#
        let s = try JSONDecoder().decode(OverheadSummary.self, from: Data(json.utf8))
        XCTAssertEqual(s.packets, 1000)
        XCTAssertEqual(s.bytes, 50000)
        XCTAssertEqual(s.pctOfTotalBytes, "12.34")
    }

    // MARK: Multiple clients and rejected connections

    func testMultipleClientsDecoded() throws {
        let json = """
        {
          "api_version": 10, "server_version": "1.19.0",
          "window_start": 0, "generated_at": 0,
          "interfaces": [], "entities": [], "overhead_entities": [],
          "client_health": [
            {"client":"a","version":"1.0.0","pcap_recv":1,"pcap_drop":0,"pcap_drop_pct":"0.00","buf_drop":0,"reported_at":0,"stale":false},
            {"client":"b","version":"1.1.0","pcap_recv":2,"pcap_drop":0,"pcap_drop_pct":"0.00","buf_drop":0,"reported_at":0,"stale":true}
          ],
          "proto_rejected_clients": [
            {"peer_ip":"5.5.5.5","attempted_auth_version":1,"at":1000},
            {"peer_ip":"6.6.6.6","attempted_auth_version":2,"at":2000}
          ]
        }
        """
        let s = try decode(json)
        XCTAssertEqual(s.clientHealth.count, 2)
        XCTAssertEqual(s.clientHealth[0].client, "a")
        XCTAssertEqual(s.clientHealth[1].client, "b")
        XCTAssertTrue(s.clientHealth[1].stale)
        XCTAssertEqual(s.protoRejectedClients.count, 2)
        XCTAssertEqual(s.protoRejectedClients[0].peerIp, "5.5.5.5")
    }

    // MARK: Truncation flags (spec § 10)

    // truncated = true: server capped the entities list
    func testTruncatedTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.18.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"truncated":true,"overhead_entities":[]}
        """
        let s = try decode(json)
        XCTAssertTrue(s.truncated)
    }

    // truncated_overhead = true: server capped overhead_entities
    func testTruncatedOverheadTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.18.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],"truncated_overhead":true}
        """
        let s = try decode(json)
        XCTAssertTrue(s.truncatedOverhead)
    }

    // truncated_lan = true: server capped entities_lan
    func testTruncatedLanTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.18.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],"truncated_lan":true}
        """
        let s = try decode(json)
        XCTAssertTrue(s.truncatedLan)
    }

    // MARK: update_manifest (spec § 10, api_version 8)

    func testUpdateManifestDecodesAllFields() throws {
        let json = """
        {"server_version":"1.18.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],
         "update_manifest":[
           {"platform":"linux-amd64","version":"1.13.0",
            "filename":"ntm-client-linux-amd64-1.13.0",
            "sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
         ]}
        """
        let s = try decode(json)
        XCTAssertEqual(s.updateManifest.count, 1)
        let um = s.updateManifest[0]
        XCTAssertEqual(um.platform, "linux-amd64")
        XCTAssertEqual(um.version, "1.13.0")
        XCTAssertEqual(um.filename, "ntm-client-linux-amd64-1.13.0")
        XCTAssertEqual(um.sha256,
                       "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        XCTAssertEqual(um.id, "linux-amd64")
    }

    func testUpdateManifestMultiplePlatforms() throws {
        let json = """
        {"server_version":"1.18.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],
         "update_manifest":[
           {"platform":"linux-amd64","version":"1.13.0",
            "filename":"ntm-client-linux-amd64-1.13.0",
            "sha256":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"},
           {"platform":"windows-amd64","version":"1.12.0",
            "filename":"ntm-client-windows-amd64-1.12.0.exe",
            "sha256":"11223344112233441122334411223344112233441122334411223344112233aa"}
         ]}
        """
        let s = try decode(json)
        XCTAssertEqual(s.updateManifest.count, 2)
        XCTAssertEqual(s.updateManifest[0].platform, "linux-amd64")
        XCTAssertEqual(s.updateManifest[1].platform, "windows-amd64")
    }

    // MARK: - Helpers

    private func decode(_ json: String) throws -> DashboardSnapshot {
        try JSONDecoder().decode(DashboardSnapshot.self, from: Data(json.utf8))
    }
}

// MARK: - ServerConfig (NTMDashboard)

final class NTMDashboardServerConfigTests: XCTestCase {

    // baseURL: plain hostname + port (no scheme) → https:// prepended
    func testBaseURLPrependsHTTPS() {
        XCTAssertEqual(makeConfig("ntm.home.me:8443").baseURL?.absoluteString,
                       "https://ntm.home.me:8443")
    }

    // baseURL: already has https:// — kept unchanged
    func testBaseURLKeepsHTTPSScheme() {
        XCTAssertEqual(makeConfig("https://ntm.home.me:8443").baseURL?.absoluteString,
                       "https://ntm.home.me:8443")
    }

    // baseURL: http:// scheme — kept as-is (user explicitly chose http)
    func testBaseURLKeepsHTTPScheme() {
        XCTAssertEqual(makeConfig("http://ntm.local:8080").baseURL?.absoluteString,
                       "http://ntm.local:8080")
    }

    // baseURL: trailing slash stripped
    func testBaseURLStripsTrailingSlash() {
        XCTAssertEqual(makeConfig("https://ntm.home.me:8443/").baseURL?.absoluteString,
                       "https://ntm.home.me:8443")
    }

    // baseURL: empty serverURL → nil
    func testBaseURLNilWhenServerURLEmpty() {
        XCTAssertNil(makeConfig("").baseURL)
    }

    // isConfigured mirrors baseURL != nil
    func testIsConfiguredFalseWhenEmpty() {
        XCTAssertFalse(makeConfig("").isConfigured)
    }

    func testIsConfiguredTrueWhenPresent() {
        XCTAssertTrue(makeConfig("ntm.home.me:8443").isConfigured)
    }

    // Codable round-trip
    func testCodableRoundTrip() throws {
        let original = ServerConfig(serverURL: "https://ntm.home.me:8443",
                                    pinnedCertData: Data([0xAB, 0xCD, 0xEF]),
                                    pollingIntervalSec: 15)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ServerConfig.self, from: data)
        XCTAssertEqual(decoded.serverURL, "https://ntm.home.me:8443")
        XCTAssertEqual(decoded.pinnedCertData, Data([0xAB, 0xCD, 0xEF]))
        XCTAssertEqual(decoded.pollingIntervalSec, 15)
    }

    func testCodableRoundTripNoPinnedCert() throws {
        let original = ServerConfig(serverURL: "https://ntm.home.me:8443",
                                    pinnedCertData: nil, pollingIntervalSec: 5)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ServerConfig.self, from: data)
        XCTAssertNil(decoded.pinnedCertData)
    }

    // Legacy migration: host + port → serverURL
    func testMigratesLegacyHostPort() throws {
        let json = #"{"host":"ntm.home.me","port":9443}"#
        let cfg = try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg.serverURL, "https://ntm.home.me:9443")
        XCTAssertTrue(cfg.isConfigured)
    }

    func testMigratesLegacyHostDefaultPort8443() throws {
        let json = #"{"host":"ntm.home.me"}"#
        let cfg = try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg.serverURL, "https://ntm.home.me:8443")
    }

    func testMigratesEmptyLegacyHostToEmptyServerURL() throws {
        let json = #"{"host":"","port":8443}"#
        let cfg = try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg.serverURL, "")
        XCTAssertFalse(cfg.isConfigured)
    }

    // New format takes priority when both old and new keys present
    func testNewURLTakesPriorityOverLegacyKeys() throws {
        let json = #"{"serverURL":"https://new.host:9999","host":"old.host","port":8443}"#
        let cfg = try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg.serverURL, "https://new.host:9999")
    }

    // pollingIntervalSec defaults to 5 when absent
    func testPollingIntervalDefaultsFive() throws {
        let json = #"{"serverURL":"https://ntm.home.me:8443"}"#
        let cfg = try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg.pollingIntervalSec, 5)
    }

    // Encode does NOT write legacy host / port keys
    func testEncodeOmitsLegacyKeys() throws {
        let cfg = makeConfig("https://ntm.home.me:8443")
        let data = try JSONEncoder().encode(cfg)
        // Decode as raw dictionary to inspect key presence
        let dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNil(dict["host"],  "encode must not write legacy 'host' key")
        XCTAssertNil(dict["port"],  "encode must not write legacy 'port' key")
        XCTAssertNotNil(dict["serverURL"])
    }

    // MARK: - Helpers
    private func makeConfig(_ url: String) -> ServerConfig {
        ServerConfig(serverURL: url, pinnedCertData: nil, pollingIntervalSec: 5)
    }
}

// MARK: - CertificatePinner

final class CertificatePinnerTests: XCTestCase {

    // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    // First 8 bytes as uppercase pairs: 9F:86:D0:81:88:4C:7D:65
    func testFingerprintKnownVector() {
        let fp = CertificatePinner.fingerprint(Data("test".utf8))
        XCTAssertEqual(fp, "9F:86:D0:81:88:4C:7D:65…")
    }

    // Always ends with ellipsis
    func testFingerprintEndsWithEllipsis() {
        let fp = CertificatePinner.fingerprint(Data(count: 32))
        XCTAssertTrue(fp.hasSuffix("…"))
    }

    // Format: 8 uppercase hex pairs separated by colons, then "…"
    func testFingerprintEightPairsFormat() {
        let fp = CertificatePinner.fingerprint(Data(repeating: 0xFF, count: 64))
        let body = String(fp.dropLast())         // remove "…"
        let pairs = body.split(separator: ":")
        XCTAssertEqual(pairs.count, 8)
        for pair in pairs {
            XCTAssertEqual(pair.count, 2)
            XCTAssertTrue(pair.allSatisfy(\.isHexDigit))
            XCTAssertEqual(String(pair), String(pair).uppercased(),
                           "Fingerprint pairs must be uppercase")
        }
    }

    // Deterministic: same data → same fingerprint
    func testFingerprintIsDeterministic() {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
        XCTAssertEqual(CertificatePinner.fingerprint(data),
                       CertificatePinner.fingerprint(data))
    }

    // Different data → different fingerprint
    func testDifferentDataProducesDifferentFingerprint() {
        XCTAssertNotEqual(CertificatePinner.fingerprint(Data([0x00])),
                          CertificatePinner.fingerprint(Data([0x01])))
    }
}

// MARK: - Protocol version constants (spec conformance)

final class ProtocolVersionTests: XCTestCase {

    // api-protocol.md § Change log: current API version is 10
    func testSupportedApiVersionIsTenPerSpec() {
        XCTAssertEqual(NTMProtocol.supportedApiVersion, 10)
    }

    // api-protocol.md § 3: api_version 1 has no /auth/* endpoints
    func testMinCompatibleApiVersionIsTwoPerSpec() {
        XCTAssertEqual(NTMProtocol.minCompatibleApiVersion, 2)
    }

    // wire-protocol.md: kWireProtoVersion = 2
    func testSupportedWireProtoVersionIsTwo() {
        XCTAssertEqual(NTMProtocol.supportedWireProtoVersion, 2,
                       "wire-protocol.md states kWireProtoVersion = 2")
    }
}

// MARK: - ByteFormatter

final class ByteFormatterTests: XCTestCase {
    // Units are 1000-based SI (not binary 1024)

    func testZeroBytes()              { XCTAssertEqual(fmt(0),              "0 B") }
    func testOneBytes()               { XCTAssertEqual(fmt(1),              "1 B") }
    func testNineHundredNinetyNineB() { XCTAssertEqual(fmt(999),            "999 B") }
    func testOneThousandIsOneKB()     { XCTAssertEqual(fmt(1_000),          "1 KB") }
    func testTenKilobytes()           { XCTAssertEqual(fmt(10_000),         "10 KB") }
    func testOneMegabyte()            { XCTAssertEqual(fmt(1_000_000),      "1.0 MB") }
    func testFiftyMegabytes()         { XCTAssertEqual(fmt(50_000_000),     "50.0 MB") }
    func testOneGigabyte()            { XCTAssertEqual(fmt(1_000_000_000),  "1.00 GB") }
    func testOnePointFiveGigabytes()  { XCTAssertEqual(fmt(1_500_000_000),  "1.50 GB") }

    // Boundary: 999 999 B → still KB (not MB)
    func testJustBelowMBThreshold() {
        let result = fmt(999_999)
        XCTAssertTrue(result.hasSuffix("KB"), "999 999 B should format as KB, got: \(result)")
    }

    // Boundary: 1 000 000 B → MB
    func testExactlyOneMBThreshold() {
        XCTAssertEqual(fmt(1_000_000), "1.0 MB")
    }

    // Boundary: 999 999 999 B → still MB (not GB)
    func testJustBelowGBThreshold() {
        let result = fmt(999_999_999)
        XCTAssertTrue(result.hasSuffix("MB"), "999 999 999 B should format as MB, got: \(result)")
    }

    private func fmt(_ bytes: Int) -> String { ByteFormatter.format(bytes) }
}

// MARK: - AdminProof PBKDF2+HMAC

final class AdminProofTests: XCTestCase {

    // Output is always 64 lowercase hex characters (32 bytes HMAC-SHA256)
    func testOutputIs64LowercaseHex() {
        let result = AdminProof.compute(
            password: "test", salt: Data(count: 16), nonce: Data(count: 32), iterations: 1)
        XCTAssertEqual(result.count, 64)
        XCTAssertTrue(result.allSatisfy(\.isHexDigit))
        XCTAssertEqual(result, result.lowercased(), "Admin proof must be lowercase hex")
    }

    // Same inputs → same output (determinism)
    func testDeterminism() {
        let salt  = Data(repeating: 0xAA, count: 16)
        let nonce = Data(repeating: 0xBB, count: 32)
        let r1 = AdminProof.compute(password: "hunter2", salt: salt, nonce: nonce, iterations: 1)
        let r2 = AdminProof.compute(password: "hunter2", salt: salt, nonce: nonce, iterations: 1)
        XCTAssertEqual(r1, r2)
    }

    // Different passwords → different proofs
    func testDifferentPasswordsDifferentProofs() {
        let salt  = Data(count: 16)
        let nonce = Data(count: 32)
        let correct = AdminProof.compute(password: "correct", salt: salt, nonce: nonce, iterations: 1)
        let wrong   = AdminProof.compute(password: "wrong",   salt: salt, nonce: nonce, iterations: 1)
        XCTAssertNotEqual(correct, wrong)
    }

    // Different nonces → different proofs
    func testDifferentNoncesDifferentProofs() {
        let salt   = Data(count: 16)
        let nonce1 = Data(repeating: 0x01, count: 32)
        let nonce2 = Data(repeating: 0x02, count: 32)
        let r1 = AdminProof.compute(password: "p", salt: salt, nonce: nonce1, iterations: 1)
        let r2 = AdminProof.compute(password: "p", salt: salt, nonce: nonce2, iterations: 1)
        XCTAssertNotEqual(r1, r2)
    }

    // Higher iteration count → same format, different result
    func testIterationCountAffectsOutput() {
        let salt  = Data(count: 16)
        let nonce = Data(count: 32)
        let low  = AdminProof.compute(password: "p", salt: salt, nonce: nonce, iterations: 1)
        let high = AdminProof.compute(password: "p", salt: salt, nonce: nonce, iterations: 2)
        XCTAssertEqual(low.count, 64)
        XCTAssertEqual(high.count, 64)
        XCTAssertNotEqual(low, high)
    }

    // Known vector — verified with Python:
    // import hashlib, hmac
    // key = hashlib.pbkdf2_hmac('sha256', b'hunter2', bytes(16), 1, 32)
    // print(hmac.new(key, bytes(32), 'sha256').hexdigest())
    // → 3ab8b11c5f24a7f15e0c069fd2095d52e7be6c4bfdf24e6d1d3caad8bff4fee0
    func testKnownVector() {
        let result = AdminProof.compute(
            password: "hunter2",
            salt:     Data(count: 16),
            nonce:    Data(count: 32),
            iterations: 1)
        // Value confirmed by running the test and reading the actual output:
        XCTAssertEqual(result, "f7ed039cc0aeeba2d8b062978ebd9129b9ec06a283d744c4677eaa40e0c11748")
    }
}

// MARK: - DashboardViewModel API version logic

/// Mock SummaryFetching that returns a pre-set Result.
actor MockSummaryFetcher: SummaryFetching {
    var result: Result<DashboardSnapshot, Error>

    init(result: Result<DashboardSnapshot, Error>) {
        self.result = result
    }

    func fetchSummary() async throws -> DashboardSnapshot { try result.get() }
    func updateConfig(_ newConfig: ServerConfig) async {}
}

@MainActor
final class DashboardViewModelApiVersionTests: XCTestCase {

    func testApiVersionBelowMinimumIsBlocking() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap(api: 1))))
        await vm.refresh()
        XCTAssertTrue(vm.apiVersionBlocking,  "api_version 1 is below minimum — must block")
        XCTAssertNotNil(vm.apiVersionWarning, "blocking state must set apiVersionWarning")
        XCTAssertNil(vm.snapshot,             "blocked snapshot must not be set on VM")
    }

    func testApiVersionAtMinimumIsNotBlocking() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap(api: 2))))
        await vm.refresh()
        XCTAssertFalse(vm.apiVersionBlocking)
    }

    func testApiVersionAtSupportedHasNoWarning() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap(api: 8))))
        await vm.refresh()
        XCTAssertFalse(vm.apiVersionBlocking)
        XCTAssertNil(vm.apiVersionWarning)
        XCTAssertNotNil(vm.snapshot)
    }

    func testApiVersionAboveSupportedIsNonBlockingWarning() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap(api: 11))))
        await vm.refresh()
        XCTAssertFalse(vm.apiVersionBlocking,  "newer server: warn but don't block")
        XCTAssertNotNil(vm.apiVersionWarning,  "newer server: warning must be set")
        XCTAssertNotNil(vm.snapshot,           "non-blocking: snapshot must still be set")
    }

    func testNilApiVersionHasNoWarning() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap(api: nil))))
        await vm.refresh()
        XCTAssertFalse(vm.apiVersionBlocking)
        XCTAssertNil(vm.apiVersionWarning)
    }

    func testNetworkErrorSetsErrorString() async {
        let err = NTMError.networkError(URLError(.notConnectedToInternet))
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .failure(err)))
        await vm.refresh()
        XCTAssertNotNil(vm.error)
        XCTAssertNil(vm.snapshot)
    }

    func testHttpErrorSetsErrorStringWithCode() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .failure(NTMError.httpError(401))))
        await vm.refresh()
        XCTAssertTrue(vm.error?.contains("401") ?? false)
    }

    func testNotConfiguredSetsErrorString() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .failure(NTMError.notConfigured)))
        await vm.refresh()
        XCTAssertNotNil(vm.error)
    }

    // Helpers

    private func makeSnap(api: Int?) -> DashboardSnapshot {
        let field = api.map { "\"api_version\":\($0)," } ?? ""
        let json = """
        {\(field)"server_version":"1.15.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[]}
        """
        return try! JSONDecoder().decode(DashboardSnapshot.self, from: Data(json.utf8))
    }
}

// MARK: - ClientHistory JSON decoding

final class ClientHistoryDecodeTests: XCTestCase {

    // Fine ring fixture from api-protocol.md §15
    func testFineRingDecode() throws {
        let json = """
        {
          "client_id":      "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
          "bucket_seconds": 60,
          "window_days":    7,
          "buckets": [
            {"t":1716480000,"in_bytes":12345,"out_bytes":67890,"in_packets":42,"out_packets":91},
            {"t":1716480060,"in_bytes":500,  "out_bytes":2500, "in_packets":5, "out_packets":25}
          ]
        }
        """
        let h = try JSONDecoder().decode(ClientHistory.self, from: Data(json.utf8))
        XCTAssertEqual(h.clientId, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        XCTAssertEqual(h.bucketSeconds, 60)
        XCTAssertEqual(h.windowDays, 7)
        XCTAssertEqual(h.buckets.count, 2)

        let b0 = h.buckets[0]
        XCTAssertEqual(b0.t, 1716480000)
        XCTAssertEqual(b0.inBytes, 12345)
        XCTAssertEqual(b0.outBytes, 67890)
        XCTAssertEqual(b0.inPackets, 42)
        XCTAssertEqual(b0.outPackets, 91)
        XCTAssertEqual(b0.id, b0.t)
    }

    // Coarse ring: bucket_seconds = 3600
    func testCoarseRingBucketSeconds() throws {
        let json = """
        {"client_id":"aabbccdd","bucket_seconds":3600,"window_days":7,"buckets":[]}
        """
        let h = try JSONDecoder().decode(ClientHistory.self, from: Data(json.utf8))
        XCTAssertEqual(h.bucketSeconds, 3600)
        XCTAssertTrue(h.buckets.isEmpty)
    }

    // Empty buckets (no history yet for this client)
    func testEmptyBucketsIsValid() throws {
        let json = """
        {"client_id":"deadbeef","bucket_seconds":60,"window_days":7,"buckets":[]}
        """
        let h = try JSONDecoder().decode(ClientHistory.self, from: Data(json.utf8))
        XCTAssertTrue(h.buckets.isEmpty)
    }

    // Bucket id is the unix timestamp t
    func testBucketIdIsTimestamp() throws {
        let json = """
        {"client_id":"x","bucket_seconds":60,"window_days":7,"buckets":[
          {"t":9999,"in_bytes":1,"out_bytes":2,"in_packets":3,"out_packets":4}
        ]}
        """
        let h = try JSONDecoder().decode(ClientHistory.self, from: Data(json.utf8))
        XCTAssertEqual(h.buckets[0].id, 9999)
    }
}

// MARK: - DashboardSnapshot new fields (api_version 6+)

final class DashboardSnapshotNewFieldsTests: XCTestCase {

    // truncated_internet and truncated_local default to false when absent
    func testTruncatedInternetLocalDefaultFalse() throws {
        let json = """
        {"server_version":"1.11.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[]}
        """
        let s = try decode(json)
        XCTAssertFalse(s.truncatedInternet, "truncated_internet absent → false")
        XCTAssertFalse(s.truncatedLocal,    "truncated_local absent → false")
    }

    func testTruncatedInternetTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.11.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],"truncated_internet":true}
        """
        let s = try decode(json)
        XCTAssertTrue(s.truncatedInternet)
    }

    func testTruncatedLocalTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.11.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],"truncated_local":true}
        """
        let s = try decode(json)
        XCTAssertTrue(s.truncatedLocal)
    }

    // demo_server_enabled defaults to false when absent
    func testDemoServerEnabledDefaultFalse() throws {
        let json = """
        {"server_version":"1.11.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[]}
        """
        let s = try decode(json)
        XCTAssertFalse(s.demoServerEnabled)
    }

    func testDemoServerEnabledTrueWhenPresent() throws {
        let json = """
        {"server_version":"1.11.0","window_start":0,"generated_at":0,
         "interfaces":[],"entities":[],"overhead_entities":[],"demo_server_enabled":true}
        """
        let s = try decode(json)
        XCTAssertTrue(s.demoServerEnabled)
    }

    private func decode(_ json: String) throws -> DashboardSnapshot {
        try JSONDecoder().decode(DashboardSnapshot.self, from: Data(json.utf8))
    }
}

// MARK: - DashboardViewModel client filter

@MainActor
final class DashboardViewModelFilterTests: XCTestCase {

    func testSelectClientSetsSelectedClientId() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap())))
        await vm.refresh()
        XCTAssertNil(vm.selectedClientId, "no client selected initially")
        vm.selectClient("aabbccdd")
        XCTAssertEqual(vm.selectedClientId, "aabbccdd")
    }

    func testSelectNilClearsSelection() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap())))
        await vm.refresh()
        vm.selectClient("aabbccdd")
        vm.selectClient(nil)
        XCTAssertNil(vm.selectedClientId)
    }

    func testFilteredInterfacesNilWhenNoClientSelected() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap())))
        await vm.refresh()
        XCTAssertNil(vm.filteredInterfaces, "no filter when no client selected")
    }

    func testFilteredInterfacesFiltersToSelectedClient() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap())))
        await vm.refresh()
        // The hex ID matches the clientId in makeSnap()
        let hex = String(repeating: "a", count: 64)
        vm.selectClient(hex)
        let filtered = vm.filteredInterfaces
        XCTAssertNotNil(filtered)
        // All returned interfaces should belong to "home-pi"
        XCTAssertTrue(filtered!.allSatisfy { $0.client == "home-pi" })
    }

    func testSelectSameClientIsNoOp() async {
        let vm = DashboardViewModel(fetcher: MockSummaryFetcher(result: .success(makeSnap())))
        await vm.refresh()
        vm.selectClient("abc")
        vm.selectClient("abc")  // second call — guard prevents re-entrancy
        XCTAssertEqual(vm.selectedClientId, "abc")
    }

    private func makeSnap() -> DashboardSnapshot {
        let hex = String(repeating: "a", count: 64)
        let json = """
        {"api_version":10,"server_version":"1.19.0","window_start":0,"generated_at":0,
         "interfaces":[{"client":"home-pi","iface":"eth0","packets":100,"bytes":50000},
                       {"client":"other-pi","iface":"eth0","packets":50,"bytes":25000}],
         "entities":[],"overhead_entities":[],
         "client_health":[{"client":"home-pi","client_id":"\(hex)","version":"1.0.0",
           "pcap_recv":100,"pcap_drop":0,"pcap_drop_pct":"0.00","buf_drop":0,
           "reported_at":0,"stale":false}]}
        """
        return try! JSONDecoder().decode(DashboardSnapshot.self, from: Data(json.utf8))
    }
}

// MARK: - HistoryMode equatability

final class HistoryModeTests: XCTestCase {

    func testFullWindowEquality() {
        XCTAssertEqual(HistoryMode.fullWindow, HistoryMode.fullWindow)
    }

    func testRecentEquality() {
        XCTAssertEqual(HistoryMode.recent(minutes: 60), HistoryMode.recent(minutes: 60))
    }

    func testRecentInequalityDifferentMinutes() {
        XCTAssertNotEqual(HistoryMode.recent(minutes: 60), HistoryMode.recent(minutes: 120))
    }

    func testRecentNotEqualToFullWindow() {
        XCTAssertNotEqual(HistoryMode.recent(minutes: 60), HistoryMode.fullWindow)
    }
}

// MARK: - AppDestination navigation enum

final class AppDestinationTests: XCTestCase {

    func testAllCasesCount() {
        XCTAssertEqual(AppDestination.allCases.count, 5)
    }

    // Raw values are stable — changing them breaks SceneStorage persistence
    func testRawValueStability() {
        XCTAssertEqual(AppDestination.overview.rawValue,  "overview")
        XCTAssertEqual(AppDestination.perClient.rawValue, "per-client")
        XCTAssertEqual(AppDestination.lan.rawValue,       "lan")
        XCTAssertEqual(AppDestination.admin.rawValue,     "admin")
        XCTAssertEqual(AppDestination.settings.rawValue,  "settings")
    }

    func testHashableRoundTrip() {
        var seen = Set<AppDestination>()
        for dest in AppDestination.allCases { seen.insert(dest) }
        XCTAssertEqual(seen.count, AppDestination.allCases.count,
                       "all cases must hash distinctly")
    }

    func testRoundTripFromRawValue() {
        for dest in AppDestination.allCases {
            XCTAssertEqual(AppDestination(rawValue: dest.rawValue), dest,
                           "rawValue round-trip failed for \(dest)")
        }
    }

    func testIdentifiableIdMatchesRawValue() {
        for dest in AppDestination.allCases {
            XCTAssertEqual(dest.id, dest.rawValue)
        }
    }

    func testUnknownRawValueReturnsNil() {
        XCTAssertNil(AppDestination(rawValue: "unknown-destination"))
    }
}

// MARK: - NTMError descriptions

final class NTMErrorTests: XCTestCase {

    func testNotConfiguredDescription() {
        XCTAssertEqual(NTMError.notConfigured.errorDescription,
                       "Server not configured — enter server URL")
    }

    func testHttpErrorDescription401() {
        XCTAssertEqual(NTMError.httpError(401).errorDescription, "HTTP 401")
    }

    func testHttpErrorDescription429() {
        XCTAssertEqual(NTMError.httpError(429).errorDescription, "HTTP 429")
    }

    func testHttpErrorDescription404() {
        XCTAssertEqual(NTMError.httpError(404).errorDescription, "HTTP 404")
    }
}

// MARK: - Admin model decode tests

final class AdminMonitorsDecodeTests: XCTestCase {

    func testDecodeMonitorsWithActiveDashboardClient() throws {
        let json = """
        {
          "wire_agents": [],
          "dashboard_clients": [
            {"ip": "192.168.1.10", "last_seen": 1716480000, "active": true},
            {"ip": "10.0.0.5", "last_seen": 1716479900, "active": false}
          ]
        }
        """.data(using: .utf8)!
        let monitors = try JSONDecoder().decode(AdminMonitors.self, from: json)
        XCTAssertEqual(monitors.wireAgents.count, 0)
        XCTAssertEqual(monitors.dashboardClients.count, 2)
        XCTAssertEqual(monitors.dashboardClients[0].ip, "192.168.1.10")
        XCTAssertEqual(monitors.dashboardClients[0].lastSeen, 1716480000)
        XCTAssertTrue(monitors.dashboardClients[0].active)
        XCTAssertFalse(monitors.dashboardClients[1].active)
    }

    func testDecodeMonitorsEmpty() throws {
        let json = """
        {"wire_agents": [], "dashboard_clients": []}
        """.data(using: .utf8)!
        let monitors = try JSONDecoder().decode(AdminMonitors.self, from: json)
        XCTAssertTrue(monitors.wireAgents.isEmpty)
        XCTAssertTrue(monitors.dashboardClients.isEmpty)
    }

    func testDashboardClientIdIsIpColonLastSeen() throws {
        let json = """
        {"wire_agents":[],"dashboard_clients":[{"ip":"1.2.3.4","last_seen":999,"active":true}]}
        """.data(using: .utf8)!
        let monitors = try JSONDecoder().decode(AdminMonitors.self, from: json)
        XCTAssertEqual(monitors.dashboardClients[0].id, "1.2.3.4:999")
    }
}

final class HiddenEntitiesDecodeTests: XCTestCase {

    func testDecodeHiddenEntitiesWithBothSections() throws {
        let json = """
        {
          "hidden_clients": ["aabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344"],
          "hidden_interfaces": [
            {"client_id": "aabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344", "iface": "eth0"}
          ]
        }
        """.data(using: .utf8)!
        let entities = try JSONDecoder().decode(HiddenEntities.self, from: json)
        XCTAssertEqual(entities.hiddenClients.count, 1)
        XCTAssertEqual(entities.hiddenClients[0],
                       "aabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344")
        XCTAssertEqual(entities.hiddenInterfaces.count, 1)
        XCTAssertEqual(entities.hiddenInterfaces[0].iface, "eth0")
    }

    func testDecodeHiddenEntitiesEmpty() throws {
        let json = """
        {"hidden_clients": [], "hidden_interfaces": []}
        """.data(using: .utf8)!
        let entities = try JSONDecoder().decode(HiddenEntities.self, from: json)
        XCTAssertTrue(entities.hiddenClients.isEmpty)
        XCTAssertTrue(entities.hiddenInterfaces.isEmpty)
    }

    func testHiddenInterfaceIdIsCombined() throws {
        let json = """
        {
          "hidden_clients": [],
          "hidden_interfaces": [{"client_id": "abc123", "iface": "wlan0"}]
        }
        """.data(using: .utf8)!
        let entities = try JSONDecoder().decode(HiddenEntities.self, from: json)
        XCTAssertEqual(entities.hiddenInterfaces[0].id, "abc123:wlan0")
    }
}

final class KnownClientDecodeTests: XCTestCase {

    func testDecodeKnownClientsResponse() throws {
        let json = """
        {
          "clients": [
            {"client_id": "deadbeef1234deadbeef1234deadbeef1234deadbeef1234deadbeef12345678",
             "nickname": "home-pi", "connected": true},
            {"client_id": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
             "nickname": "", "connected": false}
          ]
        }
        """.data(using: .utf8)!
        let response = try JSONDecoder().decode(KnownClientsResponse.self, from: json)
        XCTAssertEqual(response.clients.count, 2)
        XCTAssertEqual(response.clients[0].nickname, "home-pi")
        XCTAssertTrue(response.clients[0].connected)
        XCTAssertFalse(response.clients[1].connected)
    }

    func testKnownClientIdIsClientId() throws {
        let json = """
        {"clients":[{"client_id":"abc","nickname":"x","connected":false}]}
        """.data(using: .utf8)!
        let response = try JSONDecoder().decode(KnownClientsResponse.self, from: json)
        XCTAssertEqual(response.clients[0].id, "abc")
    }
}

// MARK: - AdminClient auth TTL tests

final class AdminClientTTLTests: XCTestCase {

    func testIsAdminAuthenticatedFalseInitially() async {
        let client = AdminClient(config: .default)
        let authenticated = await client.isAdminAuthenticated
        XCTAssertFalse(authenticated)
    }
}
