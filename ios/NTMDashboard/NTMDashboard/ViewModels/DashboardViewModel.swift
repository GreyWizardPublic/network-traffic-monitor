import Foundation
import Observation

@Observable
@MainActor
final class DashboardViewModel {
    var snapshot: DashboardSnapshot?
    var error: String?
    var apiVersionWarning: String?  // non-nil = amber banner (non-blocking)
    var apiVersionBlocking = false  // true = snapshot is not displayed
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
            let fetched = try await client.fetchSummary()
            checkApiVersion(fetched.apiVersion)
            if !apiVersionBlocking {
                snapshot = fetched
                lastUpdated = .now
            }
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }

    private func checkApiVersion(_ version: Int?) {
        guard let v = version else {
            apiVersionWarning = nil
            apiVersionBlocking = false
            return
        }
        if v < NTMProtocol.minCompatibleApiVersion {
            apiVersionBlocking = true
            apiVersionWarning = "Server API version \(v) is below minimum supported version \(NTMProtocol.minCompatibleApiVersion). Please upgrade the server."
        } else if v > NTMProtocol.supportedApiVersion {
            apiVersionBlocking = false
            apiVersionWarning = "Server API version \(v) is newer than this app supports (v\(NTMProtocol.supportedApiVersion)). Some features may not display correctly. Update the app."
        } else {
            apiVersionBlocking = false
            apiVersionWarning = nil
        }
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
