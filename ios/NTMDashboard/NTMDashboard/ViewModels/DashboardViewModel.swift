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

    // Per-client history state
    var selectedClientId: String? = nil
    var historyMode: HistoryMode = .recent(minutes: 60)
    var clientHistory: ClientHistory? = nil
    var isLoadingHistory = false
    var historyError: String? = nil

    private var client: any SummaryFetching
    private var historyClient: ClientHistoryClient
    private var pollingTask: Task<Void, Never>?
    private var historyPollingTask: Task<Void, Never>?

    /// Production init — uses a real NTMClient backed by live ServerConfig.
    init() {
        let cfg = ServerConfig.load()
        client = NTMClient(config: cfg)
        historyClient = ClientHistoryClient(config: cfg)
    }

    /// Testability init — inject a mock fetcher.
    init(fetcher: any SummaryFetching) {
        client = fetcher
        historyClient = ClientHistoryClient(config: .default)
    }

    func startPolling() async {
        let cfg = ServerConfig.load()
        await client.updateConfig(cfg)
        await historyClient.updateConfig(cfg)
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

    // MARK: - Per-client history

    func selectClient(_ clientId: String?) {
        guard clientId != selectedClientId else { return }
        selectedClientId = clientId
        historyPollingTask?.cancel()
        historyPollingTask = nil
        clientHistory = nil
        historyError = nil

        guard clientId != nil else { return }
        historyPollingTask = Task {
            while !Task.isCancelled {
                await refreshHistory()
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    func setHistoryMode(_ mode: HistoryMode) {
        guard mode != historyMode else { return }
        historyMode = mode
        Task { await refreshHistory() }
    }

    func refreshHistory() async {
        guard let cid = selectedClientId else { return }
        isLoadingHistory = true
        historyError = nil
        do {
            let mode = historyMode
            clientHistory = try await historyClient.fetchHistory(clientId: cid, mode: mode)
        } catch {
            historyError = error.localizedDescription
        }
        isLoadingHistory = false
    }

    // MARK: - Derived views for client filtering

    /// Interfaces filtered to the selected client; nil means no filter applied.
    var filteredInterfaces: [InterfaceStat]? {
        guard let cid = selectedClientId, let snap = snapshot else { return nil }
        let name = snap.clientHealth.first(where: { $0.id == cid })?.client
        return name.map { n in snap.interfaces.filter { $0.client == n } }
    }

    /// Selected client's health entry, or nil if no client selected.
    var selectedClientHealth: ClientHealth? {
        guard let cid = selectedClientId else { return nil }
        return snapshot?.clientHealth.first(where: { $0.id == cid })
    }

    // MARK: - Config update

    func applyNewConfig(_ cfg: ServerConfig) async {
        await client.updateConfig(cfg)
        await historyClient.updateConfig(cfg)
        pollingTask?.cancel()
        await startPolling()
    }

    func stopPolling() {
        pollingTask?.cancel()
        pollingTask = nil
        historyPollingTask?.cancel()
        historyPollingTask = nil
    }

    // MARK: - Private

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
}
