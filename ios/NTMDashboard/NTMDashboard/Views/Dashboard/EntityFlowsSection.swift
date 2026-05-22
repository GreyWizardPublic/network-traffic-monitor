import SwiftUI

enum TrafficFilter: String, CaseIterable {
    case internet = "Internet"
    case local    = "Local"
    case overhead = "Overhead"
    case all      = "All"
}

struct EntityFlowsSection: View {
    let flows: [EntityFlow]
    let internetFlows: [EntityFlow]
    let localFlows: [EntityFlow]
    let localSummary: OverheadSummary?
    let overheadFlows: [EntityFlow]
    let overheadSummary: OverheadSummary?

    @State private var filter: TrafficFilter = .internet

    private func fmtBytes(_ bytes: Int) -> String {
        let kb = Double(bytes) / 1_000
        let mb = kb / 1_000
        let gb = mb / 1_000
        if gb >= 1 { return String(format: "%.2f GB", gb) }
        if mb >= 1 { return String(format: "%.1f MB", mb) }
        if kb >= 1 { return String(format: "%.0f KB", kb) }
        return "\(bytes) B"
    }

    private var displayFlows: [EntityFlow] {
        switch filter {
        case .internet: return Array((internetFlows.isEmpty ? flows : internetFlows).prefix(10))
        case .local:    return Array(localFlows.prefix(10))
        case .overhead: return Array(overheadFlows.prefix(10))
        case .all:
            return Array(
                (flows + overheadFlows)
                    .sorted { $0.bytes > $1.bytes }
                    .prefix(10)
            )
        }
    }

    private var emptyLabel: String {
        switch filter {
        case .internet: return "No internet flows detected"
        case .local:    return "No local traffic detected"
        case .overhead: return "No overhead flows detected"
        case .all:      return "No flow data"
        }
    }

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Top Flows", systemImage: "arrow.left.arrow.right")
                    .font(.headline)

                Picker("Filter", selection: $filter) {
                    ForEach(TrafficFilter.allCases, id: \.self) { f in
                        Text(f.rawValue).tag(f)
                    }
                }
                .pickerStyle(.segmented)

                if filter == .local, let summary = localSummary, summary.bytes > 0 {
                    HStack(spacing: 6) {
                        Image(systemName: "network")
                            .font(.caption2)
                            .foregroundStyle(Color.ntmBlue)
                        Text("Local traffic: \(fmtBytes(summary.bytes)) (\(summary.pctOfTotalBytes)%)")
                            .font(.caption)
                            .foregroundStyle(Color.ntmBlue)
                    }
                }

                if filter == .overhead || filter == .all,
                   let summary = overheadSummary, summary.bytes > 0 {
                    HStack(spacing: 6) {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                        Text("Monitoring overhead: \(fmtBytes(summary.bytes)) (\(summary.pctOfTotalBytes)%)")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                if displayFlows.isEmpty {
                    Text(emptyLabel)
                        .foregroundStyle(.secondary)
                        .font(.subheadline)
                } else {
                    ForEach(displayFlows) { flow in
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
                        if flow.id != displayFlows.last?.id { Divider() }
                    }
                }
            }
            .padding()
        }
    }
}
