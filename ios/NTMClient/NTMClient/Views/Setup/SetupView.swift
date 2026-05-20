import SwiftUI
import UniformTypeIdentifiers

struct SetupView: View {
    @Environment(SetupViewModel.self) private var vm
    @State private var showCertPicker = false
    @State private var showRegenerateConfirm = false

    var body: some View {
        @Bindable var vm = vm
        NavigationStack {
            Form {
                serverSection
                certSection
                keySection
                registrationSection
            }
            .navigationTitle("Setup")
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
            .confirmationDialog(
                "Regenerate key pair?",
                isPresented: $showRegenerateConfirm,
                titleVisibility: .visible
            ) {
                Button("Regenerate", role: .destructive) { vm.regenerateKey() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The existing key will be deleted and you will need to re-register this device on the server.")
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var serverSection: some View {
        @Bindable var vm = vm
        Section("Server") {
            TextField("Host / domain", text: $vm.config.host)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            HStack {
                Text("HTTPS port")
                Spacer()
                TextField("8443", value: $vm.config.httpsPort, format: .number)
                    .multilineTextAlignment(.trailing)
                    .keyboardType(.numberPad)
                    .frame(width: 70)
            }
            HStack {
                Text("Wire port")
                Spacer()
                TextField("5555", value: $vm.config.wirePort, format: .number)
                    .multilineTextAlignment(.trailing)
                    .keyboardType(.numberPad)
                    .frame(width: 70)
            }
            HStack {
                Text("Device nickname")
                Spacer()
                TextField(UIDevice.current.name, text: $vm.config.nickname)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
            }
        }
    }

    @ViewBuilder
    private var certSection: some View {
        Section("TLS certificate") {
            if vm.config.pinnedCertData != nil {
                HStack {
                    Label("Certificate pinned", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Spacer()
                    Button("Clear", role: .destructive) { vm.clearCert() }
                }
            } else {
                Button("Import server certificate (DER)…") {
                    showCertPicker = true
                }
            }
        } footer: {
            Text("Required only for self-signed server certificates.")
        }
    }

    @ViewBuilder
    private var keySection: some View {
        Section("Ed25519 key pair") {
            if let short = vm.pubkeyShort {
                LabeledContent("Public key") {
                    Text(short)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Button("Regenerate key pair…", role: .destructive) {
                    showRegenerateConfirm = true
                }
            } else {
                Text("No key pair generated.")
                    .foregroundStyle(.secondary)
                Button("Generate key pair") { vm.generateKey() }
                    .frame(maxWidth: .infinity)
            }
        } footer: {
            Text("The private key never leaves this device's Keychain.")
        }
    }

    @ViewBuilder
    private var registrationSection: some View {
        Section("Server registration") {
            if vm.isRegistered {
                Label("Key registered on server", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }

            if !vm.isSignedIn {
                Button {
                    Task { await vm.login() }
                } label: {
                    if vm.isLoading {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Sign in with passkey").frame(maxWidth: .infinity)
                    }
                }
                .disabled(vm.isLoading || !vm.config.isConfigured)
            } else {
                HStack {
                    Label("Signed in", systemImage: "person.crop.circle.badge.checkmark")
                        .foregroundStyle(.green)
                    Spacer()
                    Button("Sign out", role: .destructive) { vm.logout() }
                }

                Button {
                    Task { await vm.registerKey() }
                } label: {
                    if vm.isLoading {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text(vm.isRegistered ? "Re-register key" : "Register this device")
                            .frame(maxWidth: .infinity)
                    }
                }
                .disabled(vm.isLoading || vm.pubkeyHex == nil)
            }

            if let success = vm.successMessage {
                Text(success)
                    .foregroundStyle(.green)
                    .font(.caption)
            }
            if let error = vm.errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
            }
        } footer: {
            Text("Sign in with your passkey, then register this device's public key so the server will accept its wire-protocol connection.")
        }
    }
}
