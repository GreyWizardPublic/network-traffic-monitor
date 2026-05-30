import Foundation
import Security

enum KeychainService {
    // Session token from passkey login (used to authenticate the key registration API call).
    private static let sessionService = "com.ntm.NTMClient.session"

    static func saveToken(_ token: String, for serverURL: String) {
        let data = Data(token.utf8)
        // Delete first (handles upgrade from old entry stored without ThisDeviceOnly)
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: sessionService,
            kSecAttrAccount: serverURL
        ] as CFDictionary)
        SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: sessionService,
            kSecAttrAccount: serverURL,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ] as CFDictionary, nil)
    }

    static func loadToken(for serverURL: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: sessionService,
            kSecAttrAccount: serverURL,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8)
        else { return nil }
        return token
    }

    static func deleteToken(for serverURL: String) {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: sessionService,
            kSecAttrAccount: serverURL
        ] as CFDictionary)
    }
}
