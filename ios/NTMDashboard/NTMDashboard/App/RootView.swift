import SwiftUI

struct RootView: View {
    @Environment(DashboardViewModel.self) private var dashboardVM

    var body: some View {
        TabView {
            DashboardView()
                .tabItem { Label("Dashboard", systemImage: "chart.bar.fill") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gear") }
        }
        .task {
            await dashboardVM.startPolling()
        }
    }
}
