import CryptoKit
import Foundation
import Network
import Security

// Wire protocol constants (mirrors proto_client_server.hpp)
private let kAuthVersionV2: UInt8   = 0x02
private let kAuthResultOk: UInt8    = 0x00
private let kAuthSignPrefix         = Data("NTM-AUTH-v2".utf8)
private let kAuthNonceLen           = 32
private let kAuthPubkeyLen          = 32
private let kAuthSignatureLen       = 64

enum WireError: LocalizedError {
    case noKeyPair
    case notConnected
    case connectionClosed
    case authRejected

    var errorDescription: String? {
        switch self {
        case .noKeyPair:         return "No Ed25519 key pair — generate one in Setup"
        case .notConnected:      return "Not connected"
        case .connectionClosed:  return "Connection closed by server"
        case .authRejected:      return "Server rejected key — confirm it is registered"
        }
    }
}

// Wraps NWConnection: TLS handshake + Ed25519 auth + line-oriented send.
// All network I/O happens via async/await; the actor serialises access.
actor WireProtocolClient {

    private var connection: NWConnection?

    // MARK: - Public API

    // Connects, completes TLS, performs Ed25519 auth. Throws on any failure.
    // The caller is responsible for supplying the private key.
    func connect(host: String, port: UInt16, pinnedCertData: Data?,
                 privateKey: Curve25519.Signing.PrivateKey) async throws {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )
        let params = NWParameters(tls: makeTLSOptions(pinnedCertData: pinnedCertData))
        let conn   = NWConnection(to: endpoint, using: params)

        // Wait until the connection reaches .ready (TLS handshake complete).
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            // One-shot flag: NWConnection can fire multiple terminal states.
            let done = OSAllocatedUnfairLock(initialState: false)
            conn.stateUpdateHandler = { state in
                let alreadyDone = done.withLock { prev in
                    let was = prev; prev = true; return was
                }
                guard !alreadyDone else { return }
                switch state {
                case .ready:
                    cont.resume()
                case .failed(let err):
                    cont.resume(throwing: err)
                case .cancelled:
                    cont.resume(throwing: WireError.connectionClosed)
                default:
                    break
                }
            }
            conn.start(queue: .global(qos: .utility))
        }

        conn.stateUpdateHandler = nil
        self.connection = conn

        try await performAuth(conn: conn, privateKey: privateKey)
    }

    // Appends a newline and sends the line to the server.
    func sendLine(_ line: String) async throws {
        guard let conn = connection else { throw WireError.notConnected }
        var data = Data(line.utf8)
        data.append(0x0A) // LF
        try await send(data, on: conn)
    }

    // Cancels the connection. Safe to call multiple times.
    func disconnect() {
        connection?.cancel()
        connection = nil
    }

    // MARK: - Auth handshake

    private func performAuth(conn: NWConnection, privateKey: Curve25519.Signing.PrivateKey) async throws {
        // Step 1: send auth version byte
        try await send(Data([kAuthVersionV2]), on: conn)

        // Step 2: receive 32-byte nonce
        let nonce = try await receive(exactly: kAuthNonceLen, from: conn)

        // Step 3: sign (prefix ‖ nonce) and send pubkey + signature
        var message = kAuthSignPrefix
        message.append(nonce)
        let signature = try privateKey.signature(for: message)
        var frame = privateKey.publicKey.rawRepresentation  // 32 bytes
        frame.append(contentsOf: signature)                 // 64 bytes
        try await send(frame, on: conn)

        // Step 4: receive 1-byte result
        let result = try await receive(exactly: 1, from: conn)
        guard result[0] == kAuthResultOk else { throw WireError.authRejected }
    }

    // MARK: - NWConnection helpers

    private func send(_ data: Data, on conn: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) }
                else         { cont.resume() }
            })
        }
    }

    private func receive(exactly count: Int, from conn: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            conn.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, data.count == count {
                    cont.resume(returning: data)
                } else {
                    cont.resume(throwing: WireError.connectionClosed)
                }
            }
        }
    }

    // MARK: - TLS options

    private func makeTLSOptions(pinnedCertData: Data?) -> NWProtocolTLS.Options {
        let opts = NWProtocolTLS.Options()
        guard let pinnedData = pinnedCertData else { return opts }

        // Custom verify: accept only if the server's leaf cert DER matches the pinned value.
        // Mirrors CertificatePinner for URLSession — no system chain check needed.
        sec_protocol_options_set_verify_block(
            opts.securityProtocolOptions,
            { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                guard let leaf = SecTrustGetCertificateAtIndex(secTrust, 0) else {
                    complete(false)
                    return
                }
                complete((SecCertificateCopyData(leaf) as Data) == pinnedData)
            },
            .global(qos: .utility)
        )
        return opts
    }
}
