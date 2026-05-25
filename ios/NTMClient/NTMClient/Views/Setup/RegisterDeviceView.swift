import SwiftUI
import UIKit

struct RegisterDeviceView: View {
    @Environment(SetupViewModel.self) private var vm
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
                            await vm.register(adminPassword: adminPassword, deviceLabel: deviceLabel)
                        }
                    } label: {
                        if vm.isLoading {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Register").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(adminPassword.isEmpty || deviceLabel.isEmpty || vm.isLoading)
                }

                if let error = vm.errorMessage {
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
            .onAppear { deviceLabel = UIDevice.current.name }
            .onChange(of: vm.isSignedIn) { _, signedIn in
                if signedIn { dismiss() }
            }
        }
    }
}
