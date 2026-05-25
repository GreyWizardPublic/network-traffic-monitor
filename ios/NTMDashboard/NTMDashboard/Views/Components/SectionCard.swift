import SwiftUI

struct SectionCard<Content: View>: View {
    let title: LocalizedStringKey
    let systemImage: String
    @ViewBuilder let content: Content

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Label(title, systemImage: systemImage)
                    .font(.headline)
                content
            }
            .padding()
        }
    }
}
