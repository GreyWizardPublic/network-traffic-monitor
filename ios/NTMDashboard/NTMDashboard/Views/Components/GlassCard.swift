import SwiftUI

// On iOS 26+, replace .ultraThinMaterial with .glassEffect() for native Liquid Glass.
struct GlassCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
