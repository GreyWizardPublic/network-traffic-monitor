import SwiftUI

struct RegisterDeviceView: View {
    @Environment(AuthViewModel.self) private var authVM
    @Environment(\.dismiss) private var dismiss

    @State private var adminPassword = ""
    @State private var deviceLabel = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Admin credentials") {
                    SecureField("Admin password", text: $adminPassword)
                        .textContentType(.password)
                }

                Section("Device") {
                    TextField("Device label", text: $deviceLabel)
                        .autocorrectionDisabled()
                }

                Section {
                    Button {
                        Task {
                            await authVM.register(adminPassword: adminPassword, deviceLabel: deviceLabel)
                        }
                    } label: {
                        if authVM.isLoading {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Register").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(adminPassword.isEmpty || deviceLabel.isEmpty || authVM.isLoading)
                }

                if let error = authVM.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                }
            }
            .navigationTitle("Register Device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onAppear {
                deviceLabel = UIDevice.current.name
            }
        }
    }
}
