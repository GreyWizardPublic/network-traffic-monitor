import CryptoKit
import Foundation
import Security

// Manages the device's Ed25519 key pair for wire-protocol authentication.
// The private key is stored in the Keychain (not Secure Enclave —
// Secure Enclave does not support Ed25519 / Curve25519).
enum WireKeyService {
    private static let keychainService = "com.ntm.NTMClient.wirekey"
    private static let keychainAccount = "ed25519"

    static var hasKey: Bool { loadRawPrivateKey() != nil }

    // Generates a fresh key pair and stores the private key in Keychain.
    // Overwrites any existing key.
    @discardableResult
    static func generateKey() -> Curve25519.Signing.PrivateKey {
        let key = Curve25519.Signing.PrivateKey()
        store(rawKey: key.rawRepresentation)
        return key
    }

    // Loads the private key from Keychain. Returns nil if no key is stored.
    static func loadPrivateKey() -> Curve25519.Signing.PrivateKey? {
        guard let raw = loadRawPrivateKey() else { return nil }
        return try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    }

    // Returns the 64-char lowercase hex of the stored public key, or nil.
    static func publicKeyHex() -> String? {
        loadPrivateKey()?.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
    }

    // Removes the key pair from Keychain.
    static func deleteKey() {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount
        ] as CFDictionary)
    }

    // MARK: - Private

    private static func store(rawKey: Data) {
        deleteKey()
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecValueData: rawKey,
            // Accessible while the device is unlocked (screen on or recently active).
            // PacketTunnel runs only while the VPN session is active — always unlocked —
            // so WhenUnlocked is the correct and minimal accessibility for this key.
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    private static func loadRawPrivateKey() -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return data
    }
}
