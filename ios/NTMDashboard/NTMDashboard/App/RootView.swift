import SwiftUI

struct RootView: View {
    @Environment(DashboardViewModel.self) private var dashboardVM
    @Environment(AuthViewModel.self) private var authVM

    var body: some View {
        if authVM.isAuthenticated {
            TabView {
                DashboardView()
                    .tabItem { Label("Dashboard", systemImage: "chart.bar.fill") }
                SettingsView()
                    .tabItem { Label("Settings", systemImage: "gear") }
            }
            .task {
                await dashboardVM.startPolling()
            }
        } else {
            LoginView()
        }
    }
}
