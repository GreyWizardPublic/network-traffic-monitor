import SwiftUI

struct LoginView: View {
    @Environment(AuthViewModel.self)    private var authVM
    @Environment(SettingsViewModel.self) private var settingsVM
    @State private var showRegister = false
    @State private var showSettings = false

    private var serverConfigured: Bool { !ServerConfig.load().host.isEmpty }

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

                if !serverConfigured {
                    Label("Server not configured — tap the gear to add server details.", systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

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
                }
                .padding(.horizontal, 32)

                if let error = authVM.errorMessage {
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
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showSettings = true } label: {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showRegister) {
                RegisterDeviceView()
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
        }
    }
}
