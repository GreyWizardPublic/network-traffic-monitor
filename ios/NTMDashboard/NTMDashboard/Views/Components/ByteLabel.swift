import SwiftUI

struct ByteLabel: View {
    let bytes: Int

    var body: some View {
        Text(formatted)
            .font(.subheadline.monospacedDigit())
            .foregroundStyle(Color.ntmBlue)
    }

    private var formatted: String { ByteFormatter.format(bytes) }
}
