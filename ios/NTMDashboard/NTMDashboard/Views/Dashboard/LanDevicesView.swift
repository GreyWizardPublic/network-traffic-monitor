import SwiftUI

struct LanDevicesView: View {
    @Environment(DashboardViewModel.self) private var vm

    private var sortedDevices: [LanDevice] {
        (vm.snapshot?.entitiesLan ?? [])
            .sorted { ($0.inBytes + $0.outBytes) > ($1.inBytes + $1.outBytes) }
    }

    var body: some View {
        Group {
            if let snap = vm.snapshot {
                if snap.entitiesLan.isEmpty {
                    ContentUnavailableView(
                        "No LAN Devices",
                        systemImage: "network",
                        description: Text("No unidentified LAN devices have been seen yet")
                    )
                } else {
                    List {
                        if snap.truncatedLan {
                            Label("Some devices hidden — server list was truncated", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(Color.ntmAmber)
                                .listRowBackground(Color.ntmAmber.opacity(0.08))
                        }
                        ForEach(sortedDevices) { device in
                            LanDeviceRow(device: device)
                        }
                    }
                    .listStyle(.insetGrouped)
                }
            } else {
                ProgressView("Loading…")
            }
        }
        .navigationTitle("LAN Devices")
        .refreshable { await vm.refresh() }
    }
}

private struct LanDeviceRow: View {
    let device: LanDevice

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(device.hostname ?? device.ip)
                        .font(.subheadline).bold()
                    if device.hostname != nil {
                        Text(device.ip)
                            .font(.caption).foregroundStyle(.secondary).monospaced()
                    }
                    if !device.reportedBy.isEmpty {
                        Text("via \(device.reportedBy)")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down").foregroundStyle(Color.ntmGreen)
                            .font(.caption2)
                        ByteLabel(bytes: device.inBytes)
                    }
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.up").foregroundStyle(.orange)
                            .font(.caption2)
                        ByteLabel(bytes: device.outBytes)
                    }
                }
            }
        }
    }
}
