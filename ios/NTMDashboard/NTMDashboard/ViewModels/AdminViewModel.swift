import Foundation

@Observable
@MainActor
final class AdminViewModel {
    private let client: AdminClient

    // Auth state
    var isAdminAuthenticated = false
    var showPasswordSheet = false

    // Data
    var monitors: AdminMonitors?
    var hiddenEntities: HiddenEntities?
    var knownClients: [KnownClient] = []

    // Loading / error
    var isLoading = false
    var error: String?
    var actionError: String?
    var isScanningUpdates = false
    var lastScanCount: Int?

    // Pending action to run after auth
    private var pendingAction: (() async throws -> Void)?

    init(config: ServerConfig = .load()) {
        self.client = AdminClient(config: config)
    }

    func updateConfig(_ config: ServerConfig) {
        Task { await client.updateConfig(config) }
    }

    // MARK: - Auth

    func authenticate(password: String) async {
        do {
            try await client.authenticate(password: password)
            isAdminAuthenticated = await client.isAdminAuthenticated
            showPasswordSheet = false
            if let action = pendingAction {
                pendingAction = nil
                try await action()
            }
        } catch {
            actionError = error.localizedDescription
        }
    }

    func refreshAuthState() async {
        isAdminAuthenticated = await client.isAdminAuthenticated
    }

    // Run action; if not authenticated, queue it and show password sheet
    private func requireAdmin(action: @escaping () async throws -> Void) async {
        await refreshAuthState()
        if isAdminAuthenticated {
            do { try await action() } catch { actionError = error.localizedDescription }
        } else {
            pendingAction = action
            showPasswordSheet = true
        }
    }

    // MARK: - Fetch

    func fetchAll() async {
        isLoading = true
        error = nil
        await refreshAuthState()
        if isAdminAuthenticated {
            async let m: () = fetchMonitors()
            async let h: () = fetchHiddenEntities()
            async let c: () = fetchClients()
            _ = await (m, h, c)
        }
        isLoading = false
    }

    func fetchMonitors() async {
        do { monitors = try await client.monitors() }
        catch { self.error = error.localizedDescription }
    }

    func fetchHiddenEntities() async {
        do { hiddenEntities = try await client.hiddenEntities() }
        catch { self.error = error.localizedDescription }
    }

    func fetchClients() async {
        do { knownClients = try await client.clients() }
        catch { self.error = error.localizedDescription }
    }

    // MARK: - Auth-gated loads (called from navigation destination views on appear)

    /// Navigate to MonitorsView → prompts for auth if needed, then loads.
    func loadMonitors() async {
        await requireAdmin { await self.fetchMonitors() }
    }

    /// Navigate to ManageClientsView → prompts for auth if needed, then loads.
    func loadKnownClients() async {
        await requireAdmin { await self.fetchClients() }
    }

    /// Navigate to HiddenEntitiesView → prompts for auth if needed, then loads.
    func loadHiddenEntities() async {
        await requireAdmin { await self.fetchHiddenEntities() }
    }

    // MARK: - Actions

    func unhideClient(_ clientId: String) async {
        await requireAdmin {
            try await self.client.setHiddenClient(clientId, hidden: false)
            await self.fetchHiddenEntities()
        }
    }

    func hideClient(_ clientId: String) async {
        await requireAdmin {
            try await self.client.setHiddenClient(clientId, hidden: true)
            await self.fetchHiddenEntities()
        }
    }

    func unhideInterface(clientId: String, iface: String) async {
        await requireAdmin {
            try await self.client.setHiddenInterface(clientId: clientId, iface: iface, hidden: false)
            await self.fetchHiddenEntities()
        }
    }

    func hideInterface(clientId: String, iface: String) async {
        await requireAdmin {
            try await self.client.setHiddenInterface(clientId: clientId, iface: iface, hidden: true)
            await self.fetchHiddenEntities()
        }
    }

    func purgeClient(_ clientId: String) async {
        await requireAdmin {
            try await self.client.purgeClient(clientId)
            await self.fetchClients()
        }
    }

    func scanUpdates() async {
        await requireAdmin {
            self.isScanningUpdates = true
            defer { self.isScanningUpdates = false }
            let count = try await self.client.scanUpdates()
            self.lastScanCount = count
        }
    }

    func setDemoEnabled(_ enabled: Bool) async {
        await requireAdmin {
            try await self.client.setDemoEnabled(enabled)
        }
    }
}
