import SwiftUI

struct ByteLabel: View {
    let bytes: Int

    var body: some View {
        Text(formatted)
            .font(.subheadline.monospacedDigit())
            .foregroundStyle(Color.ntmBlue)
    }

    private var formatted: String {
        let kb = Double(bytes) / 1_000
        let mb = kb / 1_000
        let gb = mb / 1_000
        if gb >= 1 { return String(format: "%.2f GB", gb) }
        if mb >= 1 { return String(format: "%.1f MB", mb) }
        if kb >= 1 { return String(format: "%.0f KB", kb) }
        return "\(bytes) B"
    }
}
