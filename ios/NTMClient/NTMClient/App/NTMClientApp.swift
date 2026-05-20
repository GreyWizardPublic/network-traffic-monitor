import SwiftUI

@main
struct NTMClientApp: App {
    @State private var setupVM    = SetupViewModel()
    @State private var wireVM     = WireViewModel()
    @State private var tunnelVM   = TunnelManager()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(setupVM)
                .environment(wireVM)
                .environment(tunnelVM)
                .task { try? await tunnelVM.load() }
        }
    }
}
