import SwiftUI

struct ClientHealthSection: View {
    let clients: [ClientHealth]

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Clients", systemImage: "desktopcomputer")
                    .font(.headline)

                if clients.isEmpty {
                    Text("No clients connected")
                        .foregroundStyle(.secondary)
                        .font(.subheadline)
                } else {
                    ForEach(clients) { client in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(Color.ntmGreen)
                                        .frame(width: 8, height: 8)
                                    Text(client.client)
                                        .font(.subheadline).bold()
                                }
                                Text("v\(client.ver) · up \(formattedUptime(client.uptimeSec))")
                                    .font(.caption).foregroundStyle(.secondary)
                                Text(client.ifaces.joined(separator: ", "))
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            StatBadge(
                                label: "drop",
                                value: client.pcapDropPct + "%",
                                color: dropColor(client.pcapDropPct)
                            )
                        }
                        if client.id != clients.last?.id { Divider() }
                    }
                }
            }
            .padding()
        }
    }

    private func formattedUptime(_ sec: Int) -> String {
        let h = sec / 3600
        let m = (sec % 3600) / 60
        if h > 0 { return "\(h)h \(m)m" }
        return "\(m)m"
    }

    private func dropColor(_ pct: String) -> Color {
        guard let val = Double(pct) else { return .ntmAmber }
        if val < 0.1 { return .ntmGreen }
        if val < 1.0 { return .ntmAmber }
        return .ntmRed
    }
}
