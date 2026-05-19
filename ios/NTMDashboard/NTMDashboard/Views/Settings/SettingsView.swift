import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @Environment(SettingsViewModel.self) private var vm
    @Environment(DashboardViewModel.self) private var dashVM
    @State private var showCertPicker = false

    var body: some View {
        @Bindable var vm = vm
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("Host / IP", text: $vm.config.host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    HStack {
                        Text("Port")
                        Spacer()
                        TextField("5556", value: $vm.config.port, format: .number)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.numberPad)
                    }
                }

                Section("Authentication") {
                    SecureField("Bearer token", text: $vm.config.bearerToken)
                }

                Section("TLS") {
                    if vm.config.pinnedCertData != nil {
                        HStack {
                            Label("Certificate pinned", systemImage: "checkmark.shield.fill")
                                .foregroundStyle(Color.ntmGreen)
                            Spacer()
                            Button("Clear", role: .destructive) { vm.clearCert() }
                        }
                    } else {
                        Button("Import server certificate…") {
                            showCertPicker = true
                        }
                    }
                }

                Section("Polling") {
                    HStack {
                        Text("Interval")
                        Spacer()
                        TextField("5", value: $vm.config.pollingIntervalSec, format: .number)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.numberPad)
                        Text("s").foregroundStyle(.secondary)
                    }
                }

                Section {
                    Button("Save & reconnect") {
                        vm.save()
                        Task { await dashVM.applyNewConfig(vm.config) }
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .navigationTitle("Settings")
            .fileImporter(
                isPresented: $showCertPicker,
                allowedContentTypes: [UTType.x509Certificate]
            ) { result in
                if case .success(let url) = result,
                   url.startAccessingSecurityScopedResource(),
                   let data = try? Data(contentsOf: url) {
                    url.stopAccessingSecurityScopedResource()
                    vm.importCert(data: data)
                }
            }
        }
    }
}
