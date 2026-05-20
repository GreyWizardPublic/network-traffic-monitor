import SwiftUI

struct WireClientView: View {
    @Environment(WireClientViewModel.self) private var vm
    @State private var showRegenerateConfirm = false

    private var serverURL: String {
        ServerConfig.load().baseURL?.absoluteString ?? ""
    }

    var body: some View {
        Form {
            keyStatusSection
            if vm.pubkeyHex != nil {
                registrationSection
            }
        }
        .navigationTitle("Wire client")
        .navigationBarTitleDisplayMode(.inline)
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

    // MARK: - Sections

    @ViewBuilder
    private var keyStatusSection: some View {
        Section {
            if let short = vm.pubkeyShort {
                LabeledContent("Public key") {
                    Text(short)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                registeredBadge
            } else {
                Text("No key pair generated yet. Generate one to enable wire-protocol connections from this device.")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
        } header: {
            Text("Ed25519 key pair")
        } footer: {
            Text("The private key is stored in the device Keychain. It is never transmitted to the server.")
        }

        Section {
            if vm.pubkeyHex == nil {
                Button("Generate key pair") { vm.generateKey() }
                    .frame(maxWidth: .infinity)
            } else {
                Button("Regenerate key pair…", role: .destructive) {
                    showRegenerateConfirm = true
                }
                .frame(maxWidth: .infinity)
            }
        }
    }

    @ViewBuilder
    private var registeredBadge: some View {
        if isRegisteredOnCurrentServer {
            Label("Registered on server", systemImage: "checkmark.circle.fill")
                .foregroundStyle(Color.ntmGreen)
                .font(.callout)
        } else {
            Label("Not yet registered", systemImage: "exclamationmark.circle")
                .foregroundStyle(.secondary)
                .font(.callout)
        }
    }

    @ViewBuilder
    private var registrationSection: some View {
        Section {
            TextField("Device nickname", text: Binding(
                get: { vm.nickname },
                set: { vm.nickname = $0 }
            ))
            .autocorrectionDisabled()

            Button {
                Task { await vm.registerWithServer() }
            } label: {
                if vm.isLoading {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text(isRegisteredOnCurrentServer ? "Re-register" : "Register this device")
                        .frame(maxWidth: .infinity)
                }
            }
            .disabled(vm.isLoading || vm.nickname.isEmpty)
        } header: {
            Text("Server registration")
        } footer: {
            Text("Registers this device's public key on the server so it can authenticate over the wire protocol. Requires an active passkey session.")
        }

        if let status = vm.registrationStatus {
            Section {
                switch status {
                case .success:
                    Label("Registered successfully", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Color.ntmGreen)
                case .alreadyRegistered:
                    Label("Already registered on server", systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                }
            }
        }

        if let error = vm.errorMessage {
            Section {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
            }
        }
    }

    private var isRegisteredOnCurrentServer: Bool {
        vm.isRegistered(on: serverURL)
    }
}
