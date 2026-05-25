import SwiftUI

struct SetupView: View {
    @Environment(SetupViewModel.self) private var vm
    @State private var showRegister = false
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
            .sheet(isPresented: $showRegister) {
                RegisterDeviceView()
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var serverSection: some View {
        @Bindable var vm = vm
        Section("Server") {
            TextField("https://ntm.yourserver.com:8443", text: $vm.config.serverURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
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
                TextField("My iPhone", text: $vm.config.nickname)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
            }
            Toggle("Use WebSocket", isOn: $vm.config.useWebSocket)
        }
    }

    @ViewBuilder
    private var certSection: some View {
        Section {
            if vm.config.pinnedCertData != nil {
                HStack {
                    Label("Certificate pinned", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Spacer()
                    Button("Clear", role: .destructive) { vm.clearCert() }
                }
            } else if let fp = vm.untrustedCertFingerprint {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Certificate not trusted", systemImage: "lock.trianglebadge.exclamationmark")
                        .foregroundStyle(.orange)
                    Text("SHA-256: \(fp)")
                        .font(.caption2)
                        .monospaced()
                    Button("Trust this server's certificate") {
                        Task { await vm.trustCertAndRetry() }
                    }
                    .buttonStyle(.bordered)
                }
            }
        } header: {
            Text("TLS certificate")
        } footer: {
            Text(vm.config.pinnedCertData != nil
                 ? "Connections are pinned to this certificate."
                 : "Leave empty to use system certificate validation.")
        }
    }

    @ViewBuilder
    private var keySection: some View {
        Section {
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
        } header: {
            Text("Ed25519 key pair")
        } footer: {
            Text("The private key never leaves this device's Keychain.")
        }
    }

    @ViewBuilder
    private var registrationSection: some View {
        Section {
            if vm.isRegistered {
                Label("Key registered on server", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }

            if vm.isSignedIn {
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
            } else {
                Button {
                    Task { await vm.login() }
                } label: {
                    Label("Sign in with Passkey", systemImage: "touchid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isLoading || !vm.config.isConfigured)

                Button("Register this device…") {
                    vm.errorMessage = nil
                    showRegister = true
                }
                .disabled(vm.isLoading || !vm.config.isConfigured)

                HStack {
                    VStack { Divider() }
                    Text("or").font(.caption).foregroundStyle(.secondary)
                    VStack { Divider() }
                }

                Button {
                    Task { await vm.connectDemo() }
                } label: {
                    Label("Try Demo Server", systemImage: "play.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(vm.isLoading)
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

            if vm.isLoading {
                ProgressView().frame(maxWidth: .infinity)
            }
        } header: {
            Text("Server registration")
        } footer: {
            Text("Sign in with your passkey, then register this device's public key so the server will accept its wire-protocol connection.")
        }
    }
}
