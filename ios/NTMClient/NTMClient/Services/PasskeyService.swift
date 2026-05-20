import AuthenticationServices
import Foundation
import UIKit

@MainActor
final class PasskeyService: NSObject {
    private var registrationContinuation: CheckedContinuation<ASAuthorizationPlatformPublicKeyCredentialRegistration, Error>?
    private var assertionContinuation: CheckedContinuation<ASAuthorizationPlatformPublicKeyCredentialAssertion, Error>?

    func performRegistration(
        challenge: Data,
        rpId: String,
        userId: Data,
        userName: String
    ) async throws -> ASAuthorizationPlatformPublicKeyCredentialRegistration {
        try await withCheckedThrowingContinuation { continuation in
            self.registrationContinuation = continuation
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
            let request = provider.createCredentialRegistrationRequest(
                challenge: challenge,
                name: userName,
                userID: userId
            )
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    func performLogin(
        challenge: Data,
        rpId: String,
        allowedCredentialIds: [Data]
    ) async throws -> ASAuthorizationPlatformPublicKeyCredentialAssertion {
        try await withCheckedThrowingContinuation { continuation in
            self.assertionContinuation = continuation
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
            let request = provider.createCredentialAssertionRequest(challenge: challenge)
            request.allowedCredentials = allowedCredentialIds.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }
}

extension PasskeyService: ASAuthorizationControllerDelegate {
    nonisolated func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        Task { @MainActor in
            if let reg = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                self.registrationContinuation?.resume(returning: reg)
                self.registrationContinuation = nil
            } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                self.assertionContinuation?.resume(returning: assertion)
                self.assertionContinuation = nil
            }
        }
    }

    nonisolated func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        Task { @MainActor in
            self.registrationContinuation?.resume(throwing: error)
            self.registrationContinuation = nil
            self.assertionContinuation?.resume(throwing: error)
            self.assertionContinuation = nil
        }
    }
}

extension PasskeyService: ASAuthorizationControllerPresentationContextProviding {
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
