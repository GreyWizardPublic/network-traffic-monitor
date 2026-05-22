import Foundation
import Network
import Observation

// kClientVersion and kWireProtoVersion come from Shared/ClientVersion.swift.
private let kHealthIntervalSec: Int  = 30
private let kMaxSessionSec: Int      = 21600  // 6 hours; reconnect before this
private let kMaxBackoffSec: Double   = 60

@Observable
@MainActor
final class WireViewModel {

    enum State: Equatable {
        case idle
        case connecting
        case connected
        case failed(String)

        var label: String {
            switch self {
            case .idle:            return "Not started"
            case .connecting:      return "Connecting…"
            case .connected:       return "Connected"
            case .failed(let msg): return msg
            }
        }

        var isConnected: Bool {
            if case .connected = self { return true }
            return false
        }
    }

    var state: State = .idle

    // Counters exposed to StatusView (Phase 3 will increment these from packet capture).
    var packetsSent: UInt64 = 0
    var connectedSince: Date?

    private let client = WireProtocolClient()
    private var mainTask: Task<Void, Never>?

    // MARK: - Lifecycle

    func start(config: ServerConfig) async {
        guard state == .idle || !state.isConnected else { return }
        mainTask?.cancel()
        mainTask = Task { [weak self] in
            await self?.runLoop(config: config)
        }
    }

    func stop() {
        mainTask?.cancel()
        mainTask = nil
        Task { await client.disconnect() }
        state = .idle
        connectedSince = nil
    }

    // Called by Phase 3 packet capture to forward D lines.
    func sendDLine(_ line: String) async {
        try? await client.sendLine(line)
    }

    // MARK: - Connection loop

    private func runLoop(config: ServerConfig) async {
        guard let privateKey = WireKeyService.loadPrivateKey() else {
            state = .failed(WireError.noKeyPair.localizedDescription)
            return
        }

        var backoff: Double = 2
        var sessionStart: Date = .now

        while !Task.isCancelled {
            state = .connecting

            do {
                try await client.connect(
                    host: config.host,
                    port: UInt16(config.wirePort),
                    pinnedCertData: config.pinnedCertData,
                    privateKey: privateKey
                )

                state = .connected
                connectedSince = .now
                sessionStart   = .now
                backoff        = 2     // reset on success

                try await runSession(config: config, sessionStart: sessionStart)

            } catch {
                await client.disconnect()
                let msg = error.localizedDescription
                state = .failed(msg)
                connectedSince = nil
            }

            // Backoff before retry.
            guard !Task.isCancelled else { break }
            try? await Task.sleep(for: .seconds(backoff))
            backoff = min(backoff * 2, kMaxBackoffSec)
        }

        state = .idle
        connectedSince = nil
    }

    // Sends X/A announce, then loops sending H heartbeats.
    // Throws when the session should end (task cancelled or session too old).
    private func runSession(config: ServerConfig, sessionStart: Date) async throws {
        let nickname = config.nickname.isEmpty ? "iOS" : config.nickname

        // Announce: WAN IP is unknown on iOS without an external check — send null.
        try await client.sendLine("X null")
        for addr in localAddresses() {
            try await client.sendLine("A \(addr)")
        }

        // Heartbeat loop
        while !Task.isCancelled {
            let elapsed = Date.now.timeIntervalSince(sessionStart)
            // Reconnect before the server's 6-hour session limit.
            if elapsed >= Double(kMaxSessionSec) - 60 { return }

            try await client.sendLine(
                "H pcap_recv=\(packetsSent) pcap_drop=0 buf_drop=0 ver=\(kClientVersion)"
            )

            // Sleep in small chunks so task cancellation is responsive.
            for _ in 0..<(kHealthIntervalSec * 4) {
                guard !Task.isCancelled else { return }
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
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
            let af = Int32(sa.pointee.sa_family)

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
        // 172.16.0.0/12
        let parts = ip.split(separator: ".")
        if parts.count == 4,
           let second = UInt8(parts[1]),
           ip.hasPrefix("172."),
           second >= 16 && second <= 31 { return true }
        return false
    }
}
