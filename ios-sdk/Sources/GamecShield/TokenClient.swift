import Foundation
import Network

struct IssuedToken {
    let token: String
    let expiresAt: Int64
}

/// Asks an edge node for a token: one TLS connection, one "GET-TOKEN <device id>" frame, one JSON frame back.
/// Blocking; call it off the main thread.
enum TokenClient {
    private struct Reply: Decodable { let token: String; let expires_at: Int64 }

    static func request(node: Node, deviceId: String, timeout: TimeInterval) throws -> IssuedToken {
        let q = DispatchQueue(label: "gamec.token")
        let sem = DispatchSemaphore(value: 0)
        var connection: NWConnection?
        PinnedTLS.connect(node, timeout: timeout, queue: q) { c in
            connection = c
            sem.signal()
        }
        sem.wait() // PinnedTLS.connect always calls back, at the latest when its own timeout fires
        guard let conn = connection else { throw ShieldError.badResponse }
        defer { conn.cancel() }

        let msg = Data("GET-TOKEN \(deviceId)".utf8)
        let frame = Data([UInt8(msg.count >> 8), UInt8(msg.count & 0xff)]) + msg
        var sendError: NWError?
        conn.send(content: frame, completion: .contentProcessed { e in
            sendError = e
            sem.signal()
        })
        guard sem.wait(timeout: .now() + timeout) == .success, sendError == nil else { throw ShieldError.badResponse }

        let header = try receiveExactly(conn, 2, timeout)
        let len = Int(header[0]) << 8 | Int(header[1])
        guard len > 0, len <= 1024 else { throw ShieldError.badResponse }
        let body = try receiveExactly(conn, len, timeout)
        let r = try JSONDecoder().decode(Reply.self, from: body)
        return IssuedToken(token: r.token, expiresAt: r.expires_at)
    }

    static func receiveExactly(_ conn: NWConnection, _ count: Int, _ timeout: TimeInterval) throws -> Data {
        var buf = Data()
        while buf.count < count {
            let got = DispatchSemaphore(value: 0)
            var chunk: Data?
            conn.receive(minimumIncompleteLength: 1, maximumLength: count - buf.count) { data, _, _, error in
                if error == nil, let d = data, !d.isEmpty { chunk = d }
                got.signal()
            }
            guard got.wait(timeout: .now() + timeout) == .success, let d = chunk else { throw ShieldError.badResponse }
            buf.append(d)
        }
        return buf
    }
}

/// Keeps one valid token, asking the given nodes in order when the cached one is about to expire.
final class TokenManager {
    private let deviceId: String
    private let margin: Int64
    private let timeout: TimeInterval
    private let request: (Node, String, TimeInterval) throws -> IssuedToken
    private let clock: () -> Int64
    private let lock = NSLock()
    private var current: IssuedToken?

    init(deviceId: String, margin: Int64, timeout: TimeInterval,
         request: @escaping (Node, String, TimeInterval) throws -> IssuedToken = { try TokenClient.request(node: $0, deviceId: $1, timeout: $2) },
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.deviceId = deviceId
        self.margin = margin
        self.timeout = timeout
        self.request = request
        self.clock = clock
    }

    func get(_ nodesInOrder: [Node]) -> String? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        if let c = current, c.expiresAt - margin > now { return c.token }
        for node in nodesInOrder {
            if let t = try? request(node, deviceId, timeout) {
                current = t
                return t.token
            }
        }
        if let c = current, c.expiresAt > now { return c.token }
        return nil
    }
}
