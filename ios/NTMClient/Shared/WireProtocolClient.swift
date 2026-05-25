import CryptoKit
import Foundation
import Network
import os
import Security

// Wire protocol constants (mirrors proto_client_server.hpp)
private let kAuthVersionV3: UInt8   = 0x03   // auth v3: adds capability exchange
private let kAuthResultOk: UInt8    = 0x00
private let kCapNone: UInt8         = 0x00   // no optional features requested
private let kAuthSignPrefix         = Data("NTM-AUTH-v2".utf8)  // signature prefix unchanged
private let kAuthNonceLen           = 32
private let kAuthPubkeyLen          = 32
private let kAuthSignatureLen       = 64

enum WireError: LocalizedError {
    case noKeyPair
    case notConnected
    case connectionClosed
    case authRejected
    case badURL

    var errorDescription: String? {
        switch self {
        case .noKeyPair:         return "No Ed25519 key pair — generate one in Setup"
        case .notConnected:      return "Not connected"
        case .connectionClosed:  return "Connection closed by server"
        case .authRejected:      return "Server rejected key — confirm it is registered"
        case .badURL:            return "Could not construct wire WebSocket URL"
        }
    }
}

// MARK: - Transport protocol

// Abstracts the byte-level I/O channel: raw TLS (NWConnection) or WebSocket.
// Both implementations are actors; the protocol is non-isolated so callers can
// use it as `any WireTransport` without actor-hopping boilerplate.
protocol WireTransport: AnyObject, Sendable {
    func connect(host: String, port: UInt16, pinnedCertData: Data?) async throws
    func send(_ data: Data) async throws
    func receive(exactly count: Int) async throws -> Data
    func cancel() async
}

// MARK: - NWConnection transport (raw TLS)

actor NWConnectionTransport: WireTransport {

    private var connection: NWConnection?

    func connect(host: String, port: UInt16, pinnedCertData: Data?) async throws {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )
        let params = NWParameters(tls: makeTLSOptions(pinnedCertData: pinnedCertData))
        let conn   = NWConnection(to: endpoint, using: params)

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
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
    }

    func send(_ data: Data) async throws {
        guard let conn = connection else { throw WireError.notConnected }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) }
                else         { cont.resume() }
            })
        }
    }

    func receive(exactly count: Int) async throws -> Data {
        guard let conn = connection else { throw WireError.notConnected }
        return try await withCheckedThrowingContinuation { cont in
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

    func cancel() async {
        connection?.cancel()
        connection = nil
    }

    private func makeTLSOptions(pinnedCertData: Data?) -> NWProtocolTLS.Options {
        let opts = NWProtocolTLS.Options()

        sec_protocol_options_add_tls_application_protocol(
            opts.securityProtocolOptions, kAlpnNtmWire)

        guard let pinnedData = pinnedCertData else { return opts }

        sec_protocol_options_set_verify_block(
            opts.securityProtocolOptions,
            { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                guard let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                      let leaf = chain.first else {
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

// MARK: - WebSocket transport (for servers behind Cloudflare / HTTP-only proxies)

// Connects to wss://<host>:<port>/wire and performs byte-stream I/O over binary
// WebSocket frames.  Incoming frames are buffered so receive(exactly:) can serve
// the auth handshake's byte-counted reads.
actor WebSocketTransport: WireTransport {

    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var rxBuffer = Data()

    func connect(host: String, port: UInt16, pinnedCertData: Data?) async throws {
        guard let url = URL(string: "wss://\(host):\(port)/wire") else {
            throw WireError.badURL
        }
        let delegate = WebSocketPinDelegate(pinnedCertData: pinnedCertData)
        let sess = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
        let t    = sess.webSocketTask(with: url)
        self.session = sess
        self.task    = t
        t.resume()

        // A ping confirms the HTTP Upgrade handshake completed successfully.
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            t.sendPing { error in
                if let error { cont.resume(throwing: error) }
                else         { cont.resume() }
            }
        }
    }

    func send(_ data: Data) async throws {
        guard let task else { throw WireError.notConnected }
        try await task.send(.data(data))
    }

    func receive(exactly count: Int) async throws -> Data {
        guard let task else { throw WireError.notConnected }
        while rxBuffer.count < count {
            let msg = try await task.receive()
            switch msg {
            case .data(let d):   rxBuffer.append(d)
            case .string(let s): rxBuffer.append(Data(s.utf8))
            @unknown default:    throw WireError.connectionClosed
            }
        }
        let result = Data(rxBuffer.prefix(count))
        rxBuffer.removeFirst(count)
        return result
    }

    func cancel() async {
        task?.cancel(with: .goingAway, reason: nil)
        session?.invalidateAndCancel()
        task    = nil
        session = nil
        rxBuffer.removeAll()
    }
}

// URLSessionDelegate that enforces cert pinning for the WebSocket connection.
private final class WebSocketPinDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    let pinnedCertData: Data?
    init(pinnedCertData: Data?) { self.pinnedCertData = pinnedCertData }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod
              == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        if let pinned = pinnedCertData {
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leaf  = chain.first,
                  (SecCertificateCopyData(leaf) as Data) == pinned else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

// MARK: - WireProtocolClient

// Wraps a WireTransport: performs the Ed25519 auth handshake then exposes sendLine.
// The transport is chosen at connect time based on the `useWebSocket` flag.
actor WireProtocolClient {

    private var transport: (any WireTransport)?

    // MARK: - Public API

    func connect(host: String, port: UInt16, pinnedCertData: Data?,
                 privateKey: Curve25519.Signing.PrivateKey,
                 useWebSocket: Bool = false) async throws {
        let t: any WireTransport = useWebSocket
            ? WebSocketTransport()
            : NWConnectionTransport()
        try await t.connect(host: host, port: port, pinnedCertData: pinnedCertData)
        self.transport = t
        try await performAuth(privateKey: privateKey)
    }

    func sendLine(_ line: String) async throws {
        guard let t = transport else { throw WireError.notConnected }
        var data = Data(line.utf8)
        data.append(0x0A) // LF
        try await t.send(data)
    }

    func disconnect() async {
        await transport?.cancel()
        transport = nil
    }

    // MARK: - Auth handshake

    private func performAuth(privateKey: Curve25519.Signing.PrivateKey) async throws {
        guard let t = transport else { throw WireError.notConnected }

        // Step 1: send auth version byte (v3 — capability exchange)
        try await t.send(Data([kAuthVersionV3]))

        // Step 2: receive 32-byte nonce
        let nonce = try await t.receive(exactly: kAuthNonceLen)

        // Step 3: sign (prefix ‖ nonce) and send pubkey + signature + capability byte
        var message = kAuthSignPrefix
        message.append(nonce)
        let signature = try privateKey.signature(for: message)
        var frame = privateKey.publicKey.rawRepresentation  // 32 bytes
        frame.append(contentsOf: signature)                 // 64 bytes
        frame.append(kCapNone)                              //  1 byte
        try await t.send(frame)

        // Step 4: receive 1-byte result
        let result = try await t.receive(exactly: 1)
        guard result[0] == kAuthResultOk else { throw WireError.authRejected }

        // Step 5: receive 1-byte negotiated capability flags
        _ = try await t.receive(exactly: 1)
    }
}
