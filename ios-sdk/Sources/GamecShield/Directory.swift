import CryptoKit
import Foundation

/// Where the last good record set is kept so the app can start while DNS is unreachable.
public protocol ListStore {
    func load() -> [String]
    func save(_ records: [String])
}

public final class UserDefaultsListStore: ListStore {
    private let key = "gamec.shield.list_records"
    public init() {}
    public func load() -> [String] { UserDefaults.standard.stringArray(forKey: key) ?? [] }
    public func save(_ records: [String]) { UserDefaults.standard.set(records, forKey: key) }
}

struct NodeList {
    let nodes: [Node]
    let iat: Int64
    let exp: Int64
    let records: [String]
}

/// Parses the signed node list published as DNS TXT records (see edge/cmd/signlist for the format).
/// Throws unless a complete record set verifies against the public key and has not expired.
enum ListVerifier {
    private struct Payload: Decodable {
        struct N: Decodable { let h: String; let p: Int; let k: String }
        let v: Int
        let iat: Int64
        let exp: Int64
        let nodes: [N]
    }

    static func base64url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    private static let bareListPattern = "^[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}$"

    static func isRecord(_ r: String) -> Bool {
        r.range(of: "^[0-9]{1,3}/[0-9]{1,3}:", options: .regularExpression) != nil
            || r.range(of: bareListPattern, options: .regularExpression) != nil
    }

    static func parse(_ records: [String], publicKeyB64: String, now: Int64) throws -> NodeList {
        let gs = records.filter { isRecord($0) }
        // total -> (index -> data); only complete, unambiguous groups are tried
        var groups: [Int: [Int: String]] = [:]
        var ambiguous = Set<Int>()
        for r in gs {
            if r.range(of: bareListPattern, options: .regularExpression) != nil { // the whole list in one record
                if groups[1, default: [:]].updateValue(r, forKey: 1) != nil { ambiguous.insert(1) }
                continue
            }
            let f = r.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard f.count == 2 else { continue }
            let pos = f[0].split(separator: "/", omittingEmptySubsequences: false)
            guard pos.count == 2, let i = Int(pos[0]), let n = Int(pos[1]), i >= 1, i <= n else { continue }
            if groups[n, default: [:]].updateValue(String(f[1]), forKey: i) != nil { ambiguous.insert(n) }
        }

        var best: NodeList?
        var lastError: Error = ShieldError.badResponse
        for (n, parts) in groups where !ambiguous.contains(n) && parts.count == n {
            do {
                let body = (1...n).map { parts[$0]! }.joined()
                let l = try verify(body, publicKeyB64: publicKeyB64, now: now, records: gs)
                if best == nil || l.iat > best!.iat { best = l }
            } catch {
                lastError = error
            }
        }
        if let b = best { return b }
        throw lastError
    }

    private static func verify(_ body: String, publicKeyB64: String, now: Int64, records: [String]) throws -> NodeList {
        let f = body.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        guard f.count == 2, let payload = base64url(String(f[0])), let sigDer = base64url(String(f[1])),
              let keyDer = Data(base64Encoded: publicKeyB64),
              let key = try? P256.Signing.PublicKey(derRepresentation: keyDer),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: sigDer),
              key.isValidSignature(sig, for: payload) else { throw ShieldError.badSignature }

        let p = try JSONDecoder().decode(Payload.self, from: payload)
        guard p.v == 1, now <= p.exp else { throw ShieldError.badResponse }
        let nodes = try p.nodes.map { n -> Node in
            guard let port = UInt16(exactly: n.p) else { throw ShieldError.badResponse }
            return Node(host: n.h, port: port, pinSha256: n.k)
        }
        guard !nodes.isEmpty else { throw ShieldError.emptyNodeList }
        return NodeList(nodes: nodes, iat: p.iat, exp: p.exp, records: records)
    }
}

/// Keeps the newest verified node list. Refreshes on a timer, never accepts an older list than one already
/// seen (blocks replay of stale records), and keeps using the last good list until it really expires.
final class NodeDirectory {
    private let cfg: DiscoveryConfig
    private let queryTxt: (String) -> [String]
    private let clock: () -> Int64
    private let lock = NSLock()
    private var current: NodeList?
    private var nextTryAt: Int64 = 0

    init(cfg: DiscoveryConfig,
         queryTxt: ((String) -> [String])? = nil,
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.cfg = cfg
        self.queryTxt = queryTxt ?? { Resolvers.query(cfg: cfg, name: $0) }
        self.clock = clock
        if let saved = cfg.store?.load(), !saved.isEmpty {
            current = try? ListVerifier.parse(saved, publicKeyB64: cfg.publicKey, now: clock())
        }
    }

    func get() -> NodeList? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        let usable: NodeList? = (current != nil && now <= current!.exp) ? current : nil
        if now < nextTryAt { return usable }
        do {
            let fresh = try ListVerifier.parse(queryTxt(cfg.name), publicKeyB64: cfg.publicKey, now: now)
            if let c = current, fresh.iat < c.iat { throw ShieldError.badResponse } // older list ignored
            current = fresh
            nextTryAt = now + Int64(cfg.refreshInterval)
            cfg.store?.save(fresh.records)
            return fresh
        } catch {
            nextTryAt = now + Int64(cfg.retryInterval)
            return usable
        }
    }
}
