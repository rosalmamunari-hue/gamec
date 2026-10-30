import CryptoKit
import Foundation

final class Session {
    let nodes: [Node]
    let token: String
    let expiresAt: Int64

    init(nodes: [Node], token: String, expiresAt: Int64) {
        self.nodes = nodes
        self.token = token
        self.expiresAt = expiresAt
    }
}

enum SessionVerifier {
    private struct Envelope: Decodable { let payload: String; let sig: String }
    private struct NodeJSON: Decodable { let host: String; let port: Int; let pin: String }
    private struct Payload: Decodable { let nodes: [NodeJSON]; let token: String; let expires_at: Int64 }

    /// Parses a control-service response; throws unless the ECDSA P-256 signature verifies.
    static func parse(_ envelopeJson: Data, publicKeyB64: String) throws -> Session {
        let env = try JSONDecoder().decode(Envelope.self, from: envelopeJson)
        guard let payload = Data(base64Encoded: env.payload),
              let sigDer = Data(base64Encoded: env.sig),
              let keyDer = Data(base64Encoded: publicKeyB64),
              let key = try? P256.Signing.PublicKey(derRepresentation: keyDer),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: sigDer),
              key.isValidSignature(sig, for: payload) else { throw ShieldError.badSignature }

        let p = try JSONDecoder().decode(Payload.self, from: payload)
        let nodes = try p.nodes.map { n -> Node in
            guard let port = UInt16(exactly: n.port) else { throw ShieldError.badResponse }
            return Node(host: n.host, port: port, pinSha256: n.pin)
        }
        guard !nodes.isEmpty else { throw ShieldError.emptyNodeList }
        return Session(nodes: nodes, token: p.token, expiresAt: p.expires_at)
    }
}

func httpFetch(_ cfg: ControlConfig) throws -> Data {
    var req = URLRequest(url: cfg.url, timeoutInterval: cfg.timeout)
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.httpBody = Data("{\"device_id\":\"\(cfg.deviceId)\"}".utf8)

    var result: Result<Data, Error> = .failure(ShieldError.badResponse)
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: req) { data, resp, err in
        if let err = err {
            result = .failure(err)
        } else if let http = resp as? HTTPURLResponse, http.statusCode == 200, let data = data {
            result = .success(data)
        }
        done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + cfg.timeout + 2)
    return try result.get()
}

/// Keeps one valid session. A new one is fetched when the token is about to expire; if the control
/// service is unreachable the previous session keeps being used until its token really expires.
final class SessionManager {
    private let cfg: ControlConfig
    private let fetch: (ControlConfig) throws -> Data
    private let clock: () -> Int64
    private let lock = NSLock()
    private var current: Session?

    init(cfg: ControlConfig,
         fetch: @escaping (ControlConfig) throws -> Data = httpFetch,
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.cfg = cfg
        self.fetch = fetch
        self.clock = clock
    }

    /// A usable session, or nil if none can be had (control unreachable and nothing cached).
    func get() -> Session? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        if let c = current, c.expiresAt - Int64(cfg.refreshMargin) > now { return c }
        do {
            let s = try SessionVerifier.parse(try fetch(cfg), publicKeyB64: cfg.publicKey)
            current = s
            return s
        } catch {
            if let c = current, c.expiresAt > now { return c }
            return nil
        }
    }
}
