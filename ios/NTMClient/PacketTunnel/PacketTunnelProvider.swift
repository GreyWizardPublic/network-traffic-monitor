import CryptoKit
import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension

// NTM software version reported in H lines; keep in sync with src/version.hpp.
private let kClientVersion     = "1.8.0"
private let kHealthIntervalSec = 30
private let kMaxSessionSec     = 21600   // 6 hours
private let kMaxBackoffSec     = 60.0

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let wireClient    = WireProtocolClient()
    private var udpForwarder  = UDPForwarder()
    private var tcpRelay      = TCPRelay()
    private var wireTask:       Task<Void, Never>?
    private var isRunning      = false

    // Packet counter for H-line pcap_recv field.
    // Accessed from both the packet-read callback and the heartbeat task;
    // the counter is best-effort — benign races are acceptable for a statistic.
    private var packetCount: UInt64 = 0

    // MARK: - NEPacketTunnelProvider lifecycle

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        Task {
            do {
                // 1. Extract private key and server config from providerConfiguration.
                let (privateKey, config) = try parseProviderConfig()

                // 2. Connect to ntm-server.
                // NWConnections in the extension process bypass the tunnel automatically.
                try await wireClient.connect(
                    host: config.host,
                    port: UInt16(config.wirePort),
                    pinnedCertData: config.pinnedCertData,
                    privateKey: privateKey
                )

                // 3. Configure the virtual tunnel interface.
                let settings = makeTunnelSettings()
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    self.setTunnelNetworkSettings(settings) { error in
                        if let error { cont.resume(throwing: error) }
                        else         { cont.resume() }
                    }
                }

                // 4. Signal success — tunnel is now active.
                completionHandler(nil)

                // 5. Start wire heartbeat / reconnect loop.
                isRunning = true
                wireTask = Task { [weak self] in
                    await self?.wireSessionLoop(config: config, privateKey: privateKey)
                }

                // 6. Start the packet read loop.
                readPackets()

            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        isRunning = false
        wireTask?.cancel()
        wireTask = nil
        Task {
            await wireClient.disconnect()
            await udpForwarder.cancelAll()
            await tcpRelay.cancelAll()
            completionHandler()
        }
    }

    // MARK: - Packet read loop

    private func readPackets() {
        guard isRunning else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning else { return }

            for (data, afNum) in zip(packets, protocols) {
                guard let pkt = IPPacket.parse(data, af: afNum.int32Value) else { continue }
                self.packetCount &+= 1   // wrapping add — counter is best-effort

                // Send D-line observation.
                Task { try? await self.wireClient.sendLine(pkt.dLine) }

                let flow = self.packetFlow

                // Forward UDP (IPv4 and IPv6, including DNS).
                if pkt.proto == IPPacket.protoUDP,
                   let payload = pkt.udpPayload(in: data) {
                    Task { await self.udpForwarder.forward(packet: pkt, rawPayload: payload, into: flow) }
                }

                // Relay TCP (IPv4 and IPv6) through per-flow NWConnection.
                if pkt.proto == 6,
                   let tcp = pkt.parseTCP(in: data) {
                    Task { await self.tcpRelay.handlePacket(pkt: pkt, tcp: tcp, rawData: data, packetFlow: flow) }
                }
            }

            self.readPackets()  // continue
        }
    }

    // MARK: - Wire session loop (runs for the lifetime of the tunnel)

    private func wireSessionLoop(config: ServerConfig,
                                  privateKey: Curve25519.Signing.PrivateKey) async {
        var backoff: Double = 2
        var alreadyConnected = true  // first iteration: connected by startTunnel

        while !Task.isCancelled {
            do {
                if !alreadyConnected {
                    try await wireClient.connect(
                        host: config.host,
                        port: UInt16(config.wirePort),
                        pinnedCertData: config.pinnedCertData,
                        privateKey: privateKey
                    )
                    backoff = 2
                }
                alreadyConnected = false

                // Announce addresses.
                try await wireClient.sendLine("X null")
                for addr in localAddresses() {
                    try await wireClient.sendLine("A \(addr)")
                }

                // Heartbeat loop.
                let sessionStart = Date.now
                while !Task.isCancelled {
                    if Date.now.timeIntervalSince(sessionStart) >= Double(kMaxSessionSec) - 60 {
                        break  // reconnect before the server's 6-hour session limit
                    }
                    try await wireClient.sendLine(
                        "H pcap_recv=\(packetCount) pcap_drop=0 buf_drop=0 ver=\(kClientVersion)"
                    )
                    // Sleep in small chunks for responsive cancellation.
                    for _ in 0..<(kHealthIntervalSec * 4) {
                        guard !Task.isCancelled else { return }
                        try? await Task.sleep(for: .milliseconds(250))
                    }
                }
            } catch {
                await wireClient.disconnect()
            }

            guard !Task.isCancelled else { break }
            try? await Task.sleep(for: .seconds(backoff))
            backoff = min(backoff * 2, kMaxBackoffSec)
        }
    }

    // MARK: - Tunnel network settings

    private func makeTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.1")

        // IPv4: capture all traffic.
        let ipv4 = NEIPv4Settings(addresses: ["10.99.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4

        // IPv6: capture all traffic. UDP and TCP are relayed; D-lines sent for all packets.
        let ipv6 = NEIPv6Settings(addresses: ["fd99::1"], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        ipv6.excludedRoutes = []
        settings.ipv6Settings = ipv6

        // DNS: fixed resolvers. Custom DNS is not preserved while capture is active.
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "1.1.1.1"])

        return settings
    }

    // MARK: - Provider config parsing

    private func parseProviderConfig() throws -> (Curve25519.Signing.PrivateKey, ServerConfig) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let cfg = proto.providerConfiguration else {
            throw TunnelConfigError.missingConfiguration
        }
        guard let pkBase64 = cfg["privateKeyData"] as? String,
              let pkRaw    = Data(base64Encoded: pkBase64),
              let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: pkRaw) else {
            throw TunnelConfigError.invalidPrivateKey
        }
        guard let cfgBase64 = cfg["serverConfigData"] as? String,
              let cfgData   = Data(base64Encoded: cfgBase64),
              let config    = try? JSONDecoder().decode(ServerConfig.self, from: cfgData) else {
            throw TunnelConfigError.invalidServerConfig
        }
        return (privateKey, config)
    }

    // MARK: - Local address discovery

    private func localAddresses() -> [String] {
        var addrs: [String] = []
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let ifa0 = ifap else { return addrs }
        defer { freeifaddrs(ifap) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = ifa0
        while let ifa = cursor?.pointee {
            defer { cursor = ifa.ifa_next }
            guard let sa = ifa.ifa_addr else { continue }

            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let af  = Int32(sa.pointee.sa_family)

            switch af {
            case AF_INET:
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var addr = sin.pointee.sin_addr
                    inet_ntop(AF_INET, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                }
            case AF_INET6:
                sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    var addr = sin6.pointee.sin6_addr
                    inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                }
            default:
                continue
            }

            let ip = String(cString: buf)
            guard !ip.isEmpty, isLanAddress(ip) else { continue }
            if !addrs.contains(ip) { addrs.append(ip) }
            if addrs.count >= 64 { break }
        }
        return addrs
    }

    private func isLanAddress(_ ip: String) -> Bool {
        if ip == "127.0.0.1" || ip == "::1" { return true }
        if ip.hasPrefix("10.") { return true }
        if ip.hasPrefix("192.168.") { return true }
        if ip.hasPrefix("fe80") || ip.hasPrefix("fc") || ip.hasPrefix("fd") { return true }
        let parts = ip.split(separator: ".")
        if parts.count == 4, ip.hasPrefix("172."), let b = UInt8(parts[1]),
           b >= 16 && b <= 31 { return true }
        return false
    }
}

// MARK: - Errors

enum TunnelConfigError: LocalizedError {
    case missingConfiguration
    case invalidPrivateKey
    case invalidServerConfig

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: return "Tunnel provider configuration is missing"
        case .invalidPrivateKey:    return "Could not decode Ed25519 private key from configuration"
        case .invalidServerConfig:  return "Could not decode server configuration"
        }
    }
}
