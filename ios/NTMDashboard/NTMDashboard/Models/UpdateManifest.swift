import Foundation

/// One entry in the `update_manifest` array returned by `/api/summary` (api_version ≥ 7).
/// Each entry describes a client binary available in the server's `update_dir`.
struct UpdateManifest: Codable, Identifiable, Sendable {
    let platform: String   // e.g. "linux-amd64" or "windows-amd64"
    let version: String    // semver of the binary in update_dir
    let filename: String   // bare filename (no path)
    let sha256: String     // lowercase hex SHA-256 of the binary

    var id: String { platform }
}
