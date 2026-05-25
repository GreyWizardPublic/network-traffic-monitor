import SwiftUI

struct HiddenEntitiesView: View {
    @Environment(AdminViewModel.self) private var adminVM
    @State private var showAddSheet = false

    var body: some View {
        Group {
            if adminVM.isLoading && adminVM.hiddenEntities == nil {
                ProgressView("Loading…")
            } else {
                let entities = adminVM.hiddenEntities
                List {
                    Section("Hidden Clients") {
                        if entities?.hiddenClients.isEmpty ?? true {
                            Text("No hidden clients")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(entities?.hiddenClients ?? [], id: \.self) { clientId in
                                Text(String(clientId.prefix(16)) + "…")
                                    .monospaced()
                                    .font(.subheadline)
                                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                        Button("Unhide", role: .destructive) {
                                            Task { await adminVM.unhideClient(clientId) }
                                        }
                                    }
                            }
                        }
                    }

                    Section("Hidden Interfaces") {
                        if entities?.hiddenInterfaces.isEmpty ?? true {
                            Text("No hidden interfaces")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(entities?.hiddenInterfaces ?? []) { iface in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(iface.iface)
                                        .font(.subheadline).bold()
                                    Text(String(iface.clientId.prefix(16)) + "…")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .monospaced()
                                }
                                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                    Button("Unhide", role: .destructive) {
                                        Task {
                                            await adminVM.unhideInterface(
                                                clientId: iface.clientId,
                                                iface: iface.iface
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Hidden Entities")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showAddSheet = true } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showAddSheet) {
            AddHiddenEntitySheet()
                .environment(adminVM)
        }
        .refreshable { await adminVM.fetchHiddenEntities() }
    }
}

private struct AddHiddenEntitySheet: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(\.dismiss) private var dismiss

    @State private var selectedClientId = ""
    @State private var iface = ""
    @State private var isHidingInterface = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Client") {
                    Picker("Client", selection: $selectedClientId) {
                        Text("Select a client").tag("")
                        ForEach(adminVM.knownClients) { client in
                            Text(client.nickname.isEmpty
                                 ? String(client.clientId.prefix(16)) + "…"
                                 : client.nickname)
                                .tag(client.clientId)
                        }
                    }
                }
                Section {
                    Toggle("Hide interface only", isOn: $isHidingInterface)
                    if isHidingInterface {
                        TextField("Interface name (e.g. eth0)", text: $iface)
                    }
                }
            }
            .navigationTitle("Add Hidden Entity")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Hide") { Task { await hide() } }
                        .disabled(selectedClientId.isEmpty || (isHidingInterface && iface.isEmpty))
                }
            }
        }
    }

    private func hide() async {
        if isHidingInterface {
            await adminVM.hideInterface(clientId: selectedClientId, iface: iface)
        } else {
            await adminVM.hideClient(selectedClientId)
        }
        dismiss()
    }
}
