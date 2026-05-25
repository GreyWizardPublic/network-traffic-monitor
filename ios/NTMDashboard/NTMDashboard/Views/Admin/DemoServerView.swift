import SwiftUI

struct DemoServerView: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(DashboardViewModel.self) private var dashboardVM

    private var isDemoEnabled: Bool {
        dashboardVM.snapshot?.demoServerEnabled ?? false
    }

    var body: some View {
        List {
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Demo Mode")
                            .font(.subheadline).bold()
                        Text(isDemoEnabled
                             ? "A demo session is currently active"
                             : "Demo mode is disabled")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Demo Mode", isOn: Binding(
                        get: { isDemoEnabled },
                        set: { enabled in Task { await adminVM.setDemoEnabled(enabled) } }
                    ))
                    .labelsHidden()
                }
            } footer: {
                Text("When enabled, a time-limited demo session is started that allows unauthenticated access to a live dashboard snapshot. Useful for showcasing the server without sharing credentials.")
            }

            if let snap = dashboardVM.snapshot, snap.demo == true,
               let exp = snap.demoExpiresAt {
                Section("Active Session") {
                    HStack(spacing: 8) {
                        Image(systemName: "clock.fill")
                            .foregroundStyle(Color.ntmAmber)
                        Text(Date(timeIntervalSince1970: TimeInterval(exp)),
                             style: .timer)
                            .font(.subheadline.bold())
                            .foregroundStyle(Color.ntmAmber)
                        Text("remaining")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Demo Server")
    }
}
