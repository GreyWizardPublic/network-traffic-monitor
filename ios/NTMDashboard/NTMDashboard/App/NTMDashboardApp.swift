import SwiftUI

@main
struct NTMDashboardApp: App {
    @State private var dashboardVM = DashboardViewModel()
    @State private var settingsVM = SettingsViewModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(dashboardVM)
                .environment(settingsVM)
        }
    }
}
