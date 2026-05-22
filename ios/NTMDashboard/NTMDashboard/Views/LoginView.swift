import SwiftUI

struct LoginView: View {
    @Environment(AuthViewModel.self)     private var authVM
    @Environment(SettingsViewModel.self) private var settingsVM
    @State private var showRegister = false
    @State private var serverURLInput: String = ServerConfig.load().serverURL

    private var serverConfigured: Bool { !serverURLInput.isEmpty }

    var body: some View {
        NavigationStack {
            VStack(spacing: 40) {
                Spacer()

                VStack(spacing: 12) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 72))
                        .foregroundStyle(.tint)
                    Text("NTM Dashboard")
                        .font(.largeTitle.bold())
                    Text("Sign in to view your network traffic")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                TextField("https://ntm.yourserver.com:8443", text: $serverURLInput)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal, 32)
                    .onSubmit { saveURL() }
                    .onChange(of: serverURLInput) { saveURL() }

                VStack(spacing: 12) {
                    Button {
                        Task { await authVM.login() }
                    } label: {
                        Label("Sign in with Passkey", systemImage: "touchid")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(authVM.isLoading || !serverConfigured)

                    Button("Register this device…") {
                        authVM.errorMessage = nil
                        showRegister = true
                    }
                    .disabled(authVM.isLoading || !serverConfigured)

                    HStack {
                        VStack { Divider() }
                        Text("or").font(.caption).foregroundStyle(.secondary)
                        VStack { Divider() }
                    }

                    Button {
                        authVM.demoUnavailable = false
                        Task { await authVM.connectDemo() }
                    } label: {
                        Label("Demo Server", systemImage: "play.circle")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.bordered)
                    .disabled(authVM.isLoading)
                }
                .padding(.horizontal, 32)

                if authVM.demoUnavailable {
                    VStack(spacing: 6) {
                        Text("Demo server is currently unavailable.")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                            .multilineTextAlignment(.center)
                        if let detail = authVM.demoErrorDetail {
                            Text(detail)
                                .foregroundStyle(.secondary)
                                .font(.caption2)
                                .monospaced()
                                .multilineTextAlignment(.center)
                        }
                        Link("Visit support page",
                             destination: URL(string: "https://github.com/GreyWizardPublic/network-traffic-monitor")!)
                            .font(.caption)
                    }
                    .padding(.horizontal, 32)
                } else if let fp = authVM.untrustedCertFingerprint {
                    VStack(spacing: 8) {
                        Label("Certificate not trusted", systemImage: "lock.trianglebadge.exclamationmark")
                            .foregroundStyle(.orange)
                        Text("SHA-256: \(fp)")
                            .font(.caption2)
                            .monospaced()
                        Button("Trust this server's certificate") {
                            Task { await authVM.trustCertAndRetry() }
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding(.horizontal, 32)
                } else if let error = authVM.errorMessage {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                if authVM.isLoading {
                    ProgressView()
                }

                Spacer()
            }
            .sheet(isPresented: $showRegister) {
                RegisterDeviceView()
            }
        }
    }

    private func saveURL() {
        var cfg = ServerConfig.load()
        cfg.serverURL = serverURLInput
        cfg.save()
        settingsVM.config.serverURL = serverURLInput
    }
}
