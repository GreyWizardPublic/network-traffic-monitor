import AuthenticationServices
import Foundation
import UIKit

@MainActor
final class SIWAService: NSObject {
    private var continuation: CheckedContinuation<String, Error>?
    // Must be retained for the lifetime of the request — ASAuthorizationController does not
    // retain itself, so releasing it cancels the operation silently.
    private var activeController: ASAuthorizationController?

    func signIn() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let provider = ASAuthorizationAppleIDProvider()
            let request = provider.createRequest()
            request.requestedScopes = [.email]
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            self.activeController = controller
            controller.performRequests()
        }
    }
}

extension SIWAService: ASAuthorizationControllerDelegate {
    nonisolated func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        Task { @MainActor in
            self.activeController = nil
            guard
                let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                let tokenData = credential.identityToken,
                let identityToken = String(data: tokenData, encoding: .utf8)
            else {
                self.continuation?.resume(throwing: SIWAError.missingIdentityToken)
                self.continuation = nil
                return
            }
            self.continuation?.resume(returning: identityToken)
            self.continuation = nil
        }
    }

    nonisolated func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        Task { @MainActor in
            self.activeController = nil
            self.continuation?.resume(throwing: error)
            self.continuation = nil
        }
    }
}

extension SIWAService: ASAuthorizationControllerPresentationContextProviding {
    nonisolated func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            guard
                let scene = UIApplication.shared.connectedScenes
                    .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
                let window = scene.keyWindow
            else { return UIWindow() }
            return window
        }
    }
}

enum SIWAError: LocalizedError {
    case missingIdentityToken
    case notAdmin

    var errorDescription: String? {
        switch self {
        case .missingIdentityToken: return "Sign in with Apple did not return an identity token"
        case .notAdmin: return "Your Apple ID is not authorised as admin on this server"
        }
    }
}
