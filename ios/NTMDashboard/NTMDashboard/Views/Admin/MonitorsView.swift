import SwiftUI

struct MonitorsView: View {
    @Environment(AdminViewModel.self) private var adminVM

    var body: some View {
        Group {
            if adminVM.isLoading && adminVM.monitors == nil {
                ProgressView("Loading…")
            } else if let monitors = adminVM.monitors {
                List {
                    Section("Connected Dashboard Clients") {
                        if monitors.dashboardClients.isEmpty {
                            Text("No dashboard clients connected")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(monitors.dashboardClients) { client in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(client.ip)
                                            .font(.subheadline).bold()
                                            .monospaced()
                                        Text(Date(timeIntervalSince1970: TimeInterval(client.lastSeen)),
                                             style: .relative)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    if client.active {
                                        Label("Active", systemImage: "circle.fill")
                                            .labelStyle(.iconOnly)
                                            .foregroundStyle(Color.ntmGreen)
                                            .font(.caption)
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "No Data",
                    systemImage: "display.2",
                    description: Text("Could not load monitor data")
                )
            }
        }
        .navigationTitle("Dashboard Monitors")
        .refreshable { await adminVM.fetchMonitors() }
    }
}
