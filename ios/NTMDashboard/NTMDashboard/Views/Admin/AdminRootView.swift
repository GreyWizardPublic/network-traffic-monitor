import SwiftUI

struct AdminRootView: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(DashboardViewModel.self) private var dashboardVM

    var body: some View {
        List {
            Section("Monitoring") {
                NavigationLink {
                    MonitorsView()
                } label: {
                    Label("Dashboard Monitors", systemImage: "display.2")
                }
            }

            Section("Traffic Data") {
                NavigationLink {
                    ManageClientsView()
                } label: {
                    Label("Manage Clients", systemImage: "person.2.fill")
                }
                NavigationLink {
                    HiddenEntitiesView()
                } label: {
                    Label("Hidden Entities", systemImage: "eye.slash.fill")
                }
            }

            Section("Server") {
                NavigationLink {
                    DemoServerView()
                } label: {
                    Label("Demo Server", systemImage: "theatermasks.fill")
                }
                NavigationLink {
                    SoftwareUpdatesView()
                } label: {
                    Label("Software Updates", systemImage: "arrow.down.circle.fill")
                }
            }

            if !adminVM.isAdminAuthenticated {
                Section {
                    Label("Not authenticated — tap an action to sign in", systemImage: "lock.fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Admin")
        .sheet(isPresented: Binding(
            get: { adminVM.showPasswordSheet },
            set: { adminVM.showPasswordSheet = $0 }
        )) {
            AdminPasswordSheet()
                .environment(adminVM)
        }
        .task { await adminVM.fetchAll() }
    }
}
