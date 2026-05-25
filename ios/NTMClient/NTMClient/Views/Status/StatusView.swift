import SwiftUI

struct StatusView: View {
    @Environment(WireViewModel.self)   private var wireVM
    @Environment(SetupViewModel.self)  private var setupVM
    @Environment(TunnelManager.self)   private var tunnelVM

    var body: some View {
        NavigationStack {
            List {
                Section("Wire connection") {
                    stateRow(wireVM.state.label, color: wireStateColor)
                    if let since = wireVM.connectedSince {
                        LabeledContent("Connected since") {
                            Text(since, style: .relative)
                                .foregroundStyle(.secondary)
                        }
                    }
                    LabeledContent("Server") {
                        Text(setupVM.config.wireHost.map { "\($0):\(setupVM.config.wirePort)" } ?? "—")
                            .foregroundStyle(.secondary)
                    }
                    if setupVM.isReadyToConnect && !tunnelVM.state.isActive {
                        Button("Reconnect") {
                            wireVM.stop()
                            Task { await wireVM.start(config: setupVM.config) }
                        }
                        .disabled(wireVM.state == .connecting)
                    }
                }

                Section("Packet capture") {
                    stateRow(tunnelVM.state.label, color: tunnelStateColor)
                    Button(tunnelVM.state.isActive ? "Stop capture" : "Start capture") {
                        if tunnelVM.state.isActive {
                            tunnelVM.stop()
                        } else {
                            Task { try? await tunnelVM.start(config: setupVM.config) }
                        }
                    }
                    .disabled(!setupVM.isReadyToConnect && !tunnelVM.state.isActive)

                    Label("Custom DNS settings are replaced with 8.8.8.8 / 1.1.1.1 while active", systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Key") {
                    if let short = setupVM.pubkeyShort {
                        LabeledContent("Public key") {
                            Text(short)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        LabeledContent("Server registration") {
                            Text(setupVM.isRegistered ? "Registered" : "Not registered")
                                .foregroundStyle(setupVM.isRegistered ? .green : .secondary)
                        }
                    } else {
                        Text("No key pair — go to Setup to generate one")
                            .foregroundStyle(.secondary)
                    }
                }

                if !setupVM.isReadyToConnect {
                    Section {
                        Label(setupNotice, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .font(.callout)
                    }
                }
            }
            .navigationTitle("NTM Client")
        }
    }

    @ViewBuilder
    private func stateRow(_ label: String, color: Color) -> some View {
        HStack(spacing: 10) {
            Circle().fill(color).frame(width: 10, height: 10)
            Text(label)
        }
    }

    private var wireStateColor: Color {
        switch wireVM.state {
        case .connected:   return .green
        case .connecting:  return .yellow
        case .failed:      return .red
        case .idle:        return .gray
        }
    }

    private var tunnelStateColor: Color {
        switch tunnelVM.state {
        case .connected:     return .green
        case .connecting,
             .disconnecting: return .yellow
        case .failed:        return .red
        default:             return .gray
        }
    }

    private var setupNotice: String {
        if !setupVM.config.isConfigured { return "Server not configured" }
        if setupVM.pubkeyHex == nil     { return "No key pair generated" }
        if !setupVM.isRegistered        { return "Key not registered on server" }
        return ""
    }
}
