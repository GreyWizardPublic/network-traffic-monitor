import SwiftUI

struct ManageClientsView: View {
    @Environment(AdminViewModel.self) private var adminVM
    @State private var clientToDelete: KnownClient?

    var body: some View {
        Group {
            if adminVM.isLoading && adminVM.knownClients.isEmpty {
                ProgressView("Loading…")
            } else if adminVM.knownClients.isEmpty {
                ContentUnavailableView(
                    "No Clients",
                    systemImage: "person.2.fill",
                    description: Text("No known clients on this server")
                )
            } else {
                List {
                    ForEach(adminVM.knownClients) { client in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(client.nickname.isEmpty
                                     ? String(client.clientId.prefix(16)) + "…"
                                     : client.nickname)
                                    .font(.subheadline).bold()
                                Text(String(client.clientId.prefix(16)) + "…")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .monospaced()
                            }
                            Spacer()
                            if client.connected {
                                Label("Connected", systemImage: "circle.fill")
                                    .labelStyle(.iconOnly)
                                    .foregroundStyle(Color.ntmGreen)
                                    .font(.caption)
                            }
                        }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button("Purge", role: .destructive) {
                                clientToDelete = client
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Manage Clients")
        .refreshable { await adminVM.fetchClients() }
        .confirmationDialog(
            "Purge \(clientToDelete?.nickname ?? String((clientToDelete?.clientId ?? "").prefix(12)) + "…")?",
            isPresented: Binding(
                get: { clientToDelete != nil },
                set: { if !$0 { clientToDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Erase all data", role: .destructive) {
                if let c = clientToDelete {
                    Task { await adminVM.purgeClient(c.clientId) }
                }
                clientToDelete = nil
            }
            Button("Cancel", role: .cancel) { clientToDelete = nil }
        } message: {
            Text("This permanently removes all stored traffic data for this client. This action cannot be undone.")
        }
    }
}
