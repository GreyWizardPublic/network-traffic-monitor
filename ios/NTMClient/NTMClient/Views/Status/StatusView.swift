import SwiftUI

struct StatusView: View {
    @Environment(WireViewModel.self)  private var wireVM
    @Environment(SetupViewModel.self) private var setupVM

    var body: some View {
        NavigationStack {
            List {
                Section("Wire connection") {
                    connectionRow
                    if let since = wireVM.connectedSince {
                        LabeledContent("Connected since") {
                            Text(since, style: .relative)
                                .foregroundStyle(.secondary)
                        }
                    }
                    LabeledContent("Server") {
                        Text(setupVM.config.host.isEmpty ? "—" : "\(setupVM.config.host):\(setupVM.config.wirePort)")
                            .foregroundStyle(.secondary)
                    }
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
    private var connectionRow: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(stateColor)
                .frame(width: 10, height: 10)
            Text(wireVM.state.label)
        }
    }

    private var stateColor: Color {
        switch wireVM.state {
        case .connected:   return .green
        case .connecting:  return .yellow
        case .failed:      return .red
        case .idle:        return .gray
        }
    }

    private var setupNotice: String {
        if !setupVM.config.isConfigured  { return "Server not configured" }
        if setupVM.pubkeyHex == nil      { return "No key pair generated" }
        if !setupVM.isRegistered         { return "Key not registered on server" }
        return ""
    }
}
