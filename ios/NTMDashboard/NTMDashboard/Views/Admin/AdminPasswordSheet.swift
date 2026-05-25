import SwiftUI

struct AdminPasswordSheet: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(\.dismiss) private var dismiss

    @State private var password = ""
    @State private var isAuthenticating = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Admin password", text: $password)
                        .textContentType(.password)
                        .submitLabel(.done)
                        .onSubmit { Task { await unlock() } }
                } footer: {
                    Text("Enter the server admin password to continue.")
                }

                if let err = adminVM.actionError {
                    Section {
                        Label(err, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Color.ntmAmber)
                            .font(.caption)
                    }
                }
            }
            .navigationTitle("Admin Authentication")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Unlock") {
                        Task { await unlock() }
                    }
                    .disabled(password.isEmpty || isAuthenticating)
                }
            }
        }
    }

    private func unlock() async {
        isAuthenticating = true
        await adminVM.authenticate(password: password)
        isAuthenticating = false
        if adminVM.isAdminAuthenticated {
            dismiss()
        }
    }
}
