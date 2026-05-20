import Foundation
import NetworkExtension
import Observation

private let kProviderBundleID = "com.ntm.NTMClient.PacketTunnel"

@Observable
@MainActor
final class TunnelManager {

    enum State: Equatable {
        case unknown
        case disconnected
        case connecting
        case connected
        case disconnecting
        case failed(String)

        var label: String {
            switch self {
            case .unknown:           return "Unknown"
            case .disconnected:      return "Stopped"
            case .connecting:        return "Starting…"
            case .connected:         return "Capturing"
            case .disconnecting:     return "Stopping…"
            case .failed(let msg):   return msg
            }
        }

        var isActive: Bool {
            self == .connecting || self == .connected || self == .disconnecting
        }
    }

    var state: State = .unknown

    private var manager:        NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    deinit {
        if let obs = statusObserver {
            NotificationCenter.default.removeObserver(obs)
        }
    }

    // MARK: - Lifecycle

    // Load any existing VPN configuration from system preferences and start
    // observing VPN status changes.
    func load() async throws {
        let managers = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { cont.resume(throwing: error) }
                else         { cont.resume(returning: managers ?? []) }
            }
        }
        manager = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == kProviderBundleID
        }
        syncState()

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object:  nil,
            queue:   .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.syncState() }
        }
    }

    // Configure providerConfiguration with the current key + server config, then
    // start the VPN tunnel. iOS will show a VPN permission alert on first call.
    func start(config: ServerConfig) async throws {
        guard let pkRaw = WireKeyService.loadPrivateKey()?.rawRepresentation else {
            throw WireError.noKeyPair
        }
        let configData = try JSONEncoder().encode(config)

        if manager == nil { manager = NETunnelProviderManager() }
        let m = manager!

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = kProviderBundleID
        proto.serverAddress            = config.host
        proto.providerConfiguration    = [
            "privateKeyData":   pkRaw.base64EncodedString(),
            "serverConfigData": configData.base64EncodedString()
        ]

        m.localizedDescription  = "NTM Packet Capture"
        m.protocolConfiguration = proto
        m.isEnabled             = true

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            m.saveToPreferences { error in
                if let error { cont.resume(throwing: error) }
                else         { cont.resume() }
            }
        }

        try m.connection.startVPNTunnel()
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    // MARK: - Private

    private func syncState() {
        guard let status = manager?.connection.status else {
            state = .unknown
            return
        }
        switch status {
        case .disconnected:    state = .disconnected
        case .connecting:      state = .connecting
        case .connected:       state = .connected
        case .disconnecting:   state = .disconnecting
        case .invalid:         state = .unknown
        case .reasserting:     state = .connecting
        @unknown default:      state = .unknown
        }
    }
}
