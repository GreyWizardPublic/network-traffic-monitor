import SwiftUI
import Charts

struct PerClientHistoryView: View {
    @Environment(DashboardViewModel.self) private var vm

    @State private var isFullWindow = false
    @State private var minutes = 60

    private struct HistoryPoint: Identifiable {
        let id = UUID()
        let date: Date
        let bytes: Int
        let direction: String
    }

    private var chartData: [HistoryPoint] {
        (vm.clientHistory?.buckets ?? []).flatMap { bucket in
            let d = Date(timeIntervalSince1970: TimeInterval(bucket.t))
            return [
                HistoryPoint(date: d, bytes: bucket.inBytes,  direction: "In"),
                HistoryPoint(date: d, bytes: bucket.outBytes, direction: "Out")
            ]
        }
    }

    private var clientName: String? {
        guard let cid = vm.selectedClientId else { return nil }
        return vm.snapshot?.clientHealth.first(where: { $0.id == cid })?.client
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Client picker
                if let snap = vm.snapshot, !snap.clientHealth.isEmpty {
                    SectionCard(title: "Select Client", systemImage: "person.2.fill") {
                        ClientFilterPicker(clients: snap.clientHealth)
                    }
                }

                if vm.selectedClientId == nil {
                    ContentUnavailableView(
                        "No Client Selected",
                        systemImage: "person.2.fill",
                        description: Text("Pick a client above to view its traffic history")
                    )
                } else {
                    // Mode selector
                    SectionCard(title: LocalizedStringKey(clientName ?? "Traffic History"), systemImage: "chart.bar.fill") {
                        Picker("Mode", selection: $isFullWindow) {
                            Text("Recent").tag(false)
                            Text("Full Window").tag(true)
                        }
                        .pickerStyle(.segmented)
                        .onChange(of: isFullWindow) { _, new in
                            vm.setHistoryMode(new ? .fullWindow : .recent(minutes: minutes))
                        }

                        if !isFullWindow {
                            HStack {
                                Text("Minutes")
                                    .font(.subheadline)
                                Spacer()
                                Stepper("\(minutes) min", value: $minutes, in: 1...1440, step: 10)
                                    .fixedSize()
                                    .onChange(of: minutes) { _, new in
                                        if !isFullWindow {
                                            vm.setHistoryMode(.recent(minutes: new))
                                        }
                                    }
                            }
                        }

                        if vm.isLoadingHistory && vm.clientHistory == nil {
                            ProgressView("Loading history…")
                                .frame(maxWidth: .infinity)
                                .padding()
                        } else if let err = vm.historyError {
                            Label(err, systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(Color.ntmAmber)
                        } else if chartData.isEmpty {
                            Text("No history data for this client")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity)
                                .padding()
                        } else {
                            historyChart
                        }
                    }
                }
            }
            .padding(.horizontal)
            .padding(.bottom)
        }
        .navigationTitle("Per-Client Traffic")
        .refreshable { await vm.refreshHistory() }
    }

    @ViewBuilder
    private var historyChart: some View {
        let bucketSec = vm.clientHistory?.bucketSeconds ?? 60
        Chart(chartData) { point in
            BarMark(
                x: .value("Time", point.date, unit: bucketSec >= 3600 ? .hour : .minute),
                y: .value("Bytes", point.bytes),
                stacking: .standard
            )
            .foregroundStyle(by: .value("Direction", point.direction))
        }
        .chartForegroundStyleScale([
            "In":  Color.ntmGreen,
            "Out": Color.orange
        ])
        .chartYAxis {
            AxisMarks { value in
                AxisGridLine()
                AxisValueLabel {
                    if let v = value.as(Int.self) {
                        Text(ByteFormatter.format(v))
                            .font(.caption2)
                    }
                }
            }
        }
        .frame(height: 220)
    }
}
