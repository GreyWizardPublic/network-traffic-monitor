import SwiftUI

struct AdminPasswordSheet: View {
    @Environment(AdminViewModel.self) private var adminVM
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                VStack(spacing: 12) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(.tint)
                    Text("Admin Authentication")
                        .font(.title2.bold())
                    Text("Sign in with your Apple ID to access admin controls.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                Button {
                    Task { await adminVM.loginWithApple() }
                } label: {
                    Label("Sign in with Apple", systemImage: "apple.logo")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 4)
                }
                .buttonStyle(.borderedProminent)
                .disabled(adminVM.isAuthenticating)
                .padding(.horizontal, 32)

                if adminVM.isAuthenticating {
                    ProgressView()
                } else if let err = adminVM.actionError {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Color.ntmAmber)
                        .font(.caption)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                Spacer()
            }
            .navigationTitle("Admin Authentication")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
