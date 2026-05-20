import Foundation
import Security

enum KeychainService {
    // Session Bearer token from passkey login (used only for key registration).
    private static let sessionService = "com.ntm.NTMClient.session"

    static func saveToken(_ token: String, for serverURL: String) {
        let data = Data(token.utf8)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: sessionService,
            kSecAttrAccount: serverURL,
            kSecValueData: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
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
