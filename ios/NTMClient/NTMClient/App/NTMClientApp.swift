import SwiftUI

@main
struct NTMClientApp: App {
    @State private var setupVM = SetupViewModel()
    @State private var wireVM  = WireViewModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(setupVM)
                .environment(wireVM)
        }
    }
}
