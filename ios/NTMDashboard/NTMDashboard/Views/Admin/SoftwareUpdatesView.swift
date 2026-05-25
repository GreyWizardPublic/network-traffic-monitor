import SwiftUI

struct SoftwareUpdatesView: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(DashboardViewModel.self) private var dashboardVM

    private var manifest: [UpdateManifest] {
        dashboardVM.snapshot?.updateManifest ?? []
    }

    var body: some View {
        List {
            if let count = adminVM.lastScanCount {
                Section {
                    Label("Last scan found \(count) update\(count == 1 ? "" : "s")",
                          systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Color.ntmGreen)
                        .font(.caption)
                }
            }

            Section("Available Updates") {
                if manifest.isEmpty {
                    Text("No update binaries available")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(manifest) { entry in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.platform)
                                    .font(.subheadline).bold()
                                Text("v\(entry.version)")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(String(entry.sha256.prefix(16)) + "…")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .monospaced()
                        }
                    }
                }
            }
        }
        .navigationTitle("Software Updates")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await adminVM.scanUpdates() }
                } label: {
                    if adminVM.isScanningUpdates {
                        ProgressView()
                    } else {
                        Label("Scan", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(adminVM.isScanningUpdates)
            }
        }
    }
}
