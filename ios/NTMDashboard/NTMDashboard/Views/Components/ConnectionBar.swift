import SwiftUI

struct ConnectionBar: View {
    let isConnected: Bool
    let serverHost: String
    let lastUpdated: Date?

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(isConnected ? Color.ntmGreen : Color.ntmRed)
                .frame(width: 8, height: 8)
            Text(isConnected ? serverHost : "Disconnected")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            if let date = lastUpdated {
                Text(date, style: .relative)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(.ultraThinMaterial)
    }
}
