import SwiftUI

struct InterfacesSection: View {
    let interfaces: [InterfaceStat]

    var body: some View {
        SectionCard(title: "Interfaces", systemImage: "network") {
            if interfaces.isEmpty {
                Text("No interface data")
                    .foregroundStyle(.secondary)
                    .font(.subheadline)
            } else {
                ForEach(interfaces) { iface in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(iface.iface)
                                .font(.subheadline).bold()
                            Text(iface.client)
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            ByteLabel(bytes: iface.bytes)
                            Text("\(iface.packets) pkts")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if iface.id != interfaces.last?.id { Divider() }
                }
            }
        }
    }
}
