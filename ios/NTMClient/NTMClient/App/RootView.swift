import SwiftUI

struct RootView: View {
    @Environment(SetupViewModel.self) private var setupVM
    @Environment(WireViewModel.self)  private var wireVM
    @Environment(TunnelManager.self)  private var tunnelVM

    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Status", systemImage: "antenna.radiowaves.left.and.right") }
            SetupView()
                .tabItem { Label("Setup", systemImage: "slider.horizontal.3") }
        }
        .task {
            // Start wire connection on launch if tunnel is not already active.
            if setupVM.isReadyToConnect, !tunnelVM.state.isActive {
                await wireVM.start(config: setupVM.config)
            }
        }
        .onChange(of: setupVM.isReadyToConnect) { _, ready in
            if ready, !tunnelVM.state.isActive {
                Task { await wireVM.start(config: setupVM.config) }
            } else if !ready {
                wireVM.stop()
            }
        }
        .onChange(of: tunnelVM.state) { _, newState in
            switch newState {
            case .connected:
                // Extension owns the wire connection while VPN is active.
                wireVM.stop()
            case .disconnected, .failed:
                // Extension stopped; resume wire connection from main app.
                if setupVM.isReadyToConnect {
                    Task { await wireVM.start(config: setupVM.config) }
                }
            default:
                break
            }
        }
    }
}
