import SwiftUI

struct EntityFlowsSection: View {
    let flows: [EntityFlow]

    private var topFlows: [EntityFlow] { Array(flows.prefix(10)) }

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Top Flows", systemImage: "arrow.left.arrow.right")
                    .font(.headline)

                if topFlows.isEmpty {
                    Text("No flow data")
                        .foregroundStyle(.secondary)
                        .font(.subheadline)
                } else {
                    ForEach(topFlows) { flow in
                        HStack(spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(flow.srcEntity)
                                    .font(.caption).foregroundStyle(.secondary)
                                Image(systemName: "arrow.down")
                                    .font(.caption2).foregroundStyle(Color.ntmBlue)
                                Text(flow.dstEntity)
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            ByteLabel(bytes: flow.bytes)
                        }
                        if flow.id != topFlows.last?.id { Divider() }
                    }
                }
            }
            .padding()
        }
    }
}
