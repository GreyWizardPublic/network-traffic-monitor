import SwiftUI

struct UpdateManifestSection: View {
    let manifest: [UpdateManifest]

    var body: some View {
        SectionCard(title: "Software Updates", systemImage: "arrow.down.circle") {
            if manifest.isEmpty {
                Text("No update binaries available")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(manifest) { entry in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.platform)
                                .font(.subheadline).bold()
                            Text("v\(entry.version)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(String(entry.sha256.prefix(16)) + "…")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .monospaced()
                    }
                    if entry.id != manifest.last?.id { Divider() }
                }
            }
        }
    }
}
