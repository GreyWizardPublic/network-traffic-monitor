import SwiftUI

struct ServerInfoFooter: View {
    let serverVersion: String
    let windowStart: Int
    let generatedAt: Int

    private var windowDuration: String {
        let seconds = generatedAt - windowStart
        if seconds < 60    { return "\(seconds)s" }
        if seconds < 3600  { return "\(seconds / 60)m" }
        if seconds < 86400 { return "\(seconds / 3600)h" }
        return "\(seconds / 86400)d"
    }

    private var updatedLabel: String {
        let ago = Int(Date().timeIntervalSince1970) - generatedAt
        if ago < 0  { return "just now" }
        if ago < 60 { return "\(ago)s ago" }
        if ago < 3600 { return "\(ago / 60)m ago" }
        return "\(ago / 3600)h ago"
    }

    var body: some View {
        HStack(spacing: 12) {
            Label("v\(serverVersion)", systemImage: "server.rack")
            Spacer()
            Text("window \(windowDuration)")
            Text("·")
            Text("updated \(updatedLabel)")
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.vertical, 4)
    }
}
