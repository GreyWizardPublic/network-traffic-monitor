import SwiftUI

struct DashboardView: View {
    @Environment(DashboardViewModel.self) private var vm

    var body: some View {
        NavigationStack {
            Group {
                if vm.apiVersionBlocking, let warning = vm.apiVersionWarning {
                    ContentUnavailableView(
                        "Incompatible Server",
                        systemImage: "exclamationmark.triangle",
                        description: Text(warning)
                    )
                } else if let snap = vm.snapshot {
                    ScrollView {
                        VStack(spacing: 16) {
                            if let warning = vm.apiVersionWarning {
                                HStack(spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.ntmAmber)
                                    Text(warning)
                                        .font(.caption)
                                        .foregroundStyle(.ntmAmber)
                                }
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.ntmAmber.opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
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
                            ClientHealthSection(
                                clients: snap.clientHealth,
                                serverWireProtoVersion: snap.serverWireProtoVersion,
                                rejectedClients: snap.protoRejectedClients
                            )
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
