import SwiftUI

struct ClientHealthSection: View {
    let clients: [ClientHealth]
    let serverWireProtoVersion: Int?
    let rejectedClients: [ProtoRejectedClient]

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Clients", systemImage: "desktopcomputer")
                    .font(.headline)

                if !rejectedClients.isEmpty {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Color.ntmAmber)
                        Text("\(rejectedClients.count) connection(s) rejected — auth-protocol mismatch")
                            .font(.caption).foregroundStyle(Color.ntmAmber)
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.ntmAmber.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }

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
                                        .fill(client.stale ? Color.ntmAmber : Color.ntmGreen)
                                        .frame(width: 8, height: 8)
                                    Text(client.client)
                                        .font(.subheadline).bold()
                                    wireProtoBadge(for: client)
                                }
                                Text("v\(client.version) · \(lastSeenLabel(client.reportedAt))")
                                    .font(.caption).foregroundStyle(.secondary)
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

                if !rejectedClients.isEmpty {
                    Divider()
                    Text("Rejected connections")
                        .font(.caption).bold().foregroundStyle(.secondary)
                    ForEach(rejectedClients) { r in
                        HStack {
                            Text(r.peerIp)
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Text("auth v\(r.attemptedAuthVersion)")
                                .font(.caption).foregroundStyle(Color.ntmRed)
                            Text(lastSeenLabel(r.at))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding()
        }
    }

    @ViewBuilder
    private func wireProtoBadge(for client: ClientHealth) -> some View {
        if let ok = client.wireProtoOk, let v = client.wireProtoVersion {
            if ok {
                Text("wire v\(v)")
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(Color.ntmGreen.opacity(0.2))
                    .foregroundStyle(Color.ntmGreen)
                    .clipShape(Capsule())
            } else {
                let srv = serverWireProtoVersion.map { " (server v\($0))" } ?? ""
                Text("wire v\(v)\(srv)")
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(Color.ntmRed.opacity(0.2))
                    .foregroundStyle(Color.ntmRed)
                    .clipShape(Capsule())
            }
        }
    }

    private func lastSeenLabel(_ epoch: Int) -> String {
        let ago = Int(Date().timeIntervalSince1970) - epoch
        if ago < 0   { return "just now" }
        if ago < 60  { return "\(ago)s ago" }
        if ago < 3600 { return "\(ago / 60)m ago" }
        return "\(ago / 3600)h ago"
    }

    private func dropColor(_ pct: String) -> Color {
        guard let val = Double(pct) else { return .ntmAmber }
        if val < 0.1 { return .ntmGreen }
        if val < 1.0 { return .ntmAmber }
        return .ntmRed
    }
}
