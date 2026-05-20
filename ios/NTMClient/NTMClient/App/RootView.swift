import SwiftUI

struct RootView: View {
    @Environment(SetupViewModel.self) private var setupVM
    @Environment(WireViewModel.self)  private var wireVM

    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Status", systemImage: "antenna.radiowaves.left.and.right") }
            SetupView()
                .tabItem { Label("Setup", systemImage: "slider.horizontal.3") }
        }
        .task {
            if setupVM.isReadyToConnect {
                await wireVM.start(config: setupVM.config)
            }
        }
        .onChange(of: setupVM.isReadyToConnect) { _, ready in
            if ready {
                Task { await wireVM.start(config: setupVM.config) }
            } else {
                wireVM.stop()
            }
        }
    }
}
