import Foundation
import Observation

@Observable
@MainActor
final class SettingsViewModel {
    var config: ServerConfig = ServerConfig.load()

    func save() {
        config.save()
    }

    func importCert(data: Data) {
        config.pinnedCertData = data
    }

    func clearCert() {
        config.pinnedCertData = nil
    }
}
