import SwiftUI

enum AppDestination: String, Hashable, CaseIterable, Identifiable {
    case overview  = "overview"
    case perClient = "per-client"
    case lan       = "lan"
    case admin     = "admin"
    case settings  = "settings"

    var id: String { rawValue }

    var label: LocalizedStringKey {
        switch self {
        case .overview:  "Overview"
        case .perClient: "Per-Client Traffic"
        case .lan:       "LAN Devices"
        case .admin:     "Admin"
        case .settings:  "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .overview:  "chart.bar.fill"
        case .perClient: "person.2.fill"
        case .lan:       "network"
        case .admin:     "shield.fill"
        case .settings:  "gear"
        }
    }
}
