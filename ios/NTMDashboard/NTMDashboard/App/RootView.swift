import SwiftUI

struct RootView: View {
    @Environment(DashboardViewModel.self) private var dashboardVM
    @Environment(AuthViewModel.self) private var authVM
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(\.horizontalSizeClass) private var sizeClass

    @SceneStorage("sidebarSelection") private var selectionRaw = AppDestination.overview.rawValue

    private var sidebarSelection: Binding<AppDestination?> {
        Binding(
            get: { AppDestination(rawValue: selectionRaw) ?? .overview },
            set: { selectionRaw = ($0 ?? .overview).rawValue }
        )
    }

    var body: some View {
        if authVM.isAuthenticated {
            Group {
                if sizeClass == .compact {
                    compactLayout
                } else {
                    regularLayout
                }
            }
            .task { await dashboardVM.startPolling() }
        } else {
            LoginView()
        }
    }

    // MARK: - Compact layout (iPhone portrait, most iPhones in landscape)

    @ViewBuilder
    private var compactLayout: some View {
        TabView {
            NavigationStack { DashboardView() }
                .tabItem { Label("Dashboard", systemImage: "chart.bar.fill") }
            NavigationStack { AdminRootView() }
                .tabItem { Label("Admin", systemImage: "shield.fill") }
                .environment(adminVM)
            NavigationStack { SettingsView() }
                .tabItem { Label("Settings", systemImage: "gear") }
        }
    }

    // MARK: - Regular layout (iPad, iPhone Pro Max landscape)

    @ViewBuilder
    private var regularLayout: some View {
        NavigationSplitView {
            List(AppDestination.allCases, selection: sidebarSelection) { dest in
                Label(dest.label, systemImage: dest.systemImage)
                    .tag(dest)
            }
            .navigationTitle("NTM Dashboard")
        } detail: {
            switch sidebarSelection.wrappedValue ?? .overview {
            case .overview:
                NavigationStack { DashboardView() }
            case .settings:
                NavigationStack { SettingsView() }
            case .perClient:
                NavigationStack { PerClientHistoryView() }
            case .lan:
                NavigationStack { LanDevicesView() }
            case .admin:
                NavigationStack { AdminRootView() }
                    .environment(adminVM)
            }
        }
    }
}
