import SwiftUI

struct SettingsView: View {
    @Environment(SettingsViewModel.self) private var vm
    @Environment(DashboardViewModel.self) private var dashVM
    @Environment(AuthViewModel.self) private var authVM

    var body: some View {
        @Bindable var vm = vm
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("https://ntm.yourserver.com:8443", text: $vm.config.serverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }

                if vm.config.pinnedCertData != nil {
                    Section("TLS") {
                        if let cert = vm.config.pinnedCertData {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Label("Certificate pinned", systemImage: "checkmark.shield.fill")
                                        .foregroundStyle(Color.ntmGreen)
                                    Text("SHA-256: \(CertificatePinner.fingerprint(cert))")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                        .monospaced()
                                }
                                Spacer()
                                Button("Clear", role: .destructive) { vm.clearCert() }
                            }
                        }
                    }
                }

                Section {
                    DisclosureGroup("Advanced") {
                        SecureField("Bearer token (optional)", text: $vm.config.bearerToken)
                        HStack {
                            Text("Polling interval")
                            Spacer()
                            TextField("5", value: $vm.config.pollingIntervalSec, format: .number)
                                .multilineTextAlignment(.trailing)
                                .keyboardType(.numberPad)
                            Text("s").foregroundStyle(.secondary)
                        }
                    }
                }

                Section {
                    Button("Save & reconnect") {
                        vm.save()
                        Task { await dashVM.applyNewConfig(vm.config) }
                    }
                    .frame(maxWidth: .infinity)
                }

                if authVM.isAuthenticated {
                    Section {
                        Button("Sign out", role: .destructive) {
                            Task { await authVM.logout() }
                        }
                        .frame(maxWidth: .infinity)
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}
