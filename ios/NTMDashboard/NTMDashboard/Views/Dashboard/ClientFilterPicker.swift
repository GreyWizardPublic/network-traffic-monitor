import SwiftUI

struct ClientFilterPicker: View {
    @Environment(DashboardViewModel.self) private var vm
    let clients: [ClientHealth]

    private var selectedLabel: String {
        guard let cid = vm.selectedClientId,
              let ch = clients.first(where: { $0.id == cid }) else {
            return "All Clients"
        }
        return ch.client
    }

    var body: some View {
        HStack {
            Menu {
                Button {
                    vm.selectClient(nil)
                } label: {
                    Label("All Clients", systemImage: "person.2.fill")
                }
                Divider()
                ForEach(clients) { client in
                    Button {
                        vm.selectClient(client.id)
                    } label: {
                        if vm.selectedClientId == client.id {
                            Label(client.client, systemImage: "checkmark")
                        } else {
                            Text(client.client)
                        }
                    }
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "person.2.fill")
                        .foregroundStyle(Color.ntmBlue)
                    Text(selectedLabel)
                        .font(.subheadline)
                    Image(systemName: "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if vm.selectedClientId != nil {
                Button("Clear") { vm.selectClient(nil) }
                    .font(.caption)
                    .foregroundStyle(Color.ntmBlue)
            }
        }
        .padding(.vertical, 4)
    }
}
