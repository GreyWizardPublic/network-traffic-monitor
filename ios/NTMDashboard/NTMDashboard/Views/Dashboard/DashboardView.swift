import SwiftUI

struct DashboardView: View {
    @Environment(DashboardViewModel.self) private var vm

    var body: some View {
        NavigationStack {
            Group {
                if let snap = vm.snapshot {
                    ScrollView {
                        VStack(spacing: 16) {
                            ConnectionBar(
                                isConnected: true,
                                serverHost: ServerConfig.load().baseURL?.host() ?? "",
                                lastUpdated: vm.lastUpdated
                            )
                            InterfacesSection(interfaces: snap.interfaces)
                            EntityFlowsSection(
                                flows: snap.entities,
                                overheadFlows: snap.overheadEntities,
                                overheadSummary: snap.overheadSummary
                            )
                            ClientHealthSection(clients: snap.clientHealth)
                        }
                        .padding(.horizontal)
                        .padding(.bottom)
                    }
                    .refreshable { await vm.refresh() }
                } else if vm.isLoading {
                    ProgressView("Connecting…")
                } else if let err = vm.error {
                    ContentUnavailableView(
                        "Cannot reach server",
                        systemImage: "network.slash",
                        description: Text(err)
                    )
                } else {
                    ContentUnavailableView(
                        "Not configured",
                        systemImage: "gear.badge.xmark",
                        description: Text("Add server details in Settings")
                    )
                }
            }
            .navigationTitle("NTM Dashboard")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await vm.refresh() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(vm.isLoading)
                }
            }
        }
    }
}
