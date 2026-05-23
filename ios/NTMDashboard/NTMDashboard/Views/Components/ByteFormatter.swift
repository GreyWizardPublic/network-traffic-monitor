import Foundation

/// Pure byte-count formatting used by ByteLabel.
/// Units are 1000-based (SI): KB = 1 000 B, MB = 1 000 000 B, GB = 1 000 000 000 B.
enum ByteFormatter {
    static func format(_ bytes: Int) -> String {
        let kb = Double(bytes) / 1_000
        let mb = kb / 1_000
        let gb = mb / 1_000
        if gb >= 1 { return String(format: "%.2f GB", gb) }
        if mb >= 1 { return String(format: "%.1f MB", mb) }
        if kb >= 1 { return String(format: "%.0f KB", kb) }
        return "\(bytes) B"
    }
}
