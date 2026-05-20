import SwiftUI

@main
struct NTMDashboardApp: App {
    @State private var dashboardVM = DashboardViewModel()
    @State private var settingsVM = SettingsViewModel()
    @State private var authVM = AuthViewModel()
    @State private var wireClientVM = WireClientViewModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(dashboardVM)
                .environment(settingsVM)
                .environment(authVM)
                .environment(wireClientVM)
        }
    }
}
