import SwiftUI

@main
struct NTMDashboardApp: App {
    @State private var dashboardVM = DashboardViewModel()
    @State private var settingsVM = SettingsViewModel()
    @State private var authVM = AuthViewModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(dashboardVM)
                .environment(settingsVM)
                .environment(authVM)
        }
    }
}
