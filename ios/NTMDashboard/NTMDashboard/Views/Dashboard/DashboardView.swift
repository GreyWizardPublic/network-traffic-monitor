import SwiftUI

struct DemoBanner: View {
    let expiresAt: Int
    @State private var now: Date = .init()
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var remaining: Int {
        max(0, expiresAt - Int(now.timeIntervalSince1970))
    }

    private var label: String {
        if remaining == 0 { return "Demo session expired" }
        let m = remaining / 60
        let s = remaining % 60
        return String(format: "Demo mode — expires in %d:%02d", m, s)
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: remaining == 0 ? "clock.badge.xmark" : "clock.fill")
                .foregroundStyle(Color.ntmAmber)
            Text(label)
                .font(.caption.bold())
                .foregroundStyle(Color.ntmAmber)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.ntmAmber.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .onReceive(timer) { now = $0 }
    }
}

struct DashboardView: View {
    @Environment(DashboardViewModel.self) private var vm
    @Environment(AuthViewModel.self) private var authVM

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
                            if snap.demo == true, let exp = snap.demoExpiresAt {
                                DemoBanner(expiresAt: exp)
                            }
                            if let warning = vm.apiVersionWarning {
                                HStack(spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(Color.ntmAmber)
                                    Text(warning)
                                        .font(.caption)
                                        .foregroundStyle(Color.ntmAmber)
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
                                internetFlows: snap.entitiesInternet,
                                localFlows: snap.entitiesLocal,
                                localSummary: snap.localSummary,
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
                if vm.snapshot?.demo == true {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Sign out", role: .destructive) {
                            Task { await authVM.logout() }
                        }
                    }
                }
            }
        }
    }
}
