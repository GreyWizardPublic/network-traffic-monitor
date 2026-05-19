import SwiftUI

struct StatBadge: View {
    let label: String
    let value: String
    var color: Color = .ntmAmber

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.caption.bold().monospacedDigit())
                .foregroundStyle(color)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}
