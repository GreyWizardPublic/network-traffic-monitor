import Foundation
import Observation

@Observable
@MainActor
final class DashboardViewModel {
    var snapshot: DashboardSnapshot?
    var error: String?
    var isLoading = false
    var lastUpdated: Date?

    private var client: NTMClient
    private var pollingTask: Task<Void, Never>?

    init() {
        let cfg = ServerConfig.load()
        client = NTMClient(config: cfg)
    }

    func startPolling() async {
        let cfg = ServerConfig.load()
        await client.updateConfig(cfg)
        let interval = max(1, cfg.pollingIntervalSec)
        pollingTask?.cancel()
        pollingTask = Task {
            while !Task.isCancelled {
                await refresh()
                try? await Task.sleep(for: .seconds(interval))
            }
        }
    }

    func refresh() async {
        isLoading = true
        error = nil
        do {
            snapshot = try await client.fetchSummary()
            lastUpdated = .now
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }

    func applyNewConfig(_ cfg: ServerConfig) async {
        await client.updateConfig(cfg)
        pollingTask?.cancel()
        await startPolling()
    }

    func stopPolling() {
        pollingTask?.cancel()
        pollingTask = nil
    }
}
