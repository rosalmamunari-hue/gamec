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
    /// Names the panel says to read from next time; the ones built into the app are then only a fallback.
    var next: [String] = []
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
        let next: [String]?
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

    static func parse(_ records: [String], publicKeyB64: String, now: Int64, listKeyB64: String? = nil) throws -> NodeList {
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
        for r in records { // the compact format: each value is a whole list on its own
            guard let o = Compact.open(r, publicKeyB64: publicKeyB64, listKeyB64: listKeyB64, kind: Compact.kindList) else { continue }
            guard let nodes = Compact.nodes(o), now <= o.exp else { lastError = ShieldError.badResponse; continue }
            if best == nil || o.iat > best!.iat { best = NodeList(nodes: nodes, iat: o.iat, exp: o.exp, records: [r]) }
        }
        for (n, parts) in groups where !ambiguous.contains(n) && parts.count == n {
            do {
                let body = (1...n).map { parts[$0]! }.joined()
                let l = try verify(body, publicKeyB64: publicKeyB64, now: now, records: gs, listKeyB64: listKeyB64)
                if best == nil || l.iat > best!.iat { best = l }
            } catch {
                lastError = error
            }
        }
        if let b = best { return b }
        throw lastError
    }

    /// nonce(12) || ciphertext || tag, AES-256-GCM; nil when `data` is not sealed with this key.
    private static func unseal(_ data: Data, keyB64: String) -> Data? {
        guard let kd = Data(base64Encoded: keyB64), kd.count == 32,
              let box = try? AES.GCM.SealedBox(combined: data),
              let plain = try? AES.GCM.open(box, using: SymmetricKey(data: kd)) else { return nil }
        return plain
    }

    private static func verify(_ body: String, publicKeyB64: String, now: Int64, records: [String],
                               listKeyB64: String?) throws -> NodeList {
        let f = body.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        // an unsealed list simply fails to decrypt and is checked as it is: the signature decides
        let first = base64url(String(f.first ?? ""))
        let payloadOpt: Data? = first.flatMap { d in listKeyB64.flatMap { unseal(d, keyB64: $0) } ?? d }
        guard f.count == 2, let payload = payloadOpt, let sigDer = base64url(String(f[1])),
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
        return NodeList(nodes: nodes, iat: p.iat, exp: p.exp, records: records, next: p.next ?? [])
    }
}

/// Keeps the newest verified node list. Refreshes on a timer, never accepts an older list than one already
/// seen (blocks replay of stale records), and keeps using the last good list until it really expires.
final class NodeDirectory {
    private let cfg: DiscoveryConfig
    private let queryTxt: ((String) -> [String])? // for tests; nil = the real resolvers
    private let clock: () -> Int64
    private let lock = NSLock() // guards the fields below; never held while DNS is read
    private let reading = NSLock() // one DNS read at a time
    private var current: NodeList?
    /// iat of the newest list ever accepted, kept after that list expires: nothing older is taken.
    private var floorIat: Int64 = 0
    private var nextTryAt: Int64 = 0
    private var lastTryAt: Int64?
    /// The names to read from next time, from the dw2. record that goes with a compact list.
    private var nextNames: NextNames?
    private var nextBusy = false

    init(cfg: DiscoveryConfig,
         queryTxt: ((String) -> [String])? = nil,
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.cfg = cfg
        self.queryTxt = queryTxt
        self.clock = clock
        if let saved = cfg.store?.load(), !saved.isEmpty {
            nextNames = try? NextVerifier.parse(saved, publicKeyB64: cfg.publicKey, now: clock(), listKeyB64: cfg.listKey)
            if let l = try? ListVerifier.parse(saved, publicKeyB64: cfg.publicKey, now: clock(), listKeyB64: cfg.listKey) {
                current = l
                floorIat = l.iat
            } else if let old = try? ListVerifier.parse(saved, publicKeyB64: cfg.publicKey, now: 0,
                                                        listKeyB64: cfg.listKey) {
                // An expired saved list is not used, but it still says how new the next list must be, so a
                // replayed older one is not taken after a long time offline.
                floorIat = old.iat
            }
        }
    }

    func get() -> NodeList? { read { [self] now in now >= nextTryAt } }

    /// Re-read now because nothing worked; at most once per `urgentRefresh`.
    func refreshNow() -> NodeList? {
        read { [self] now in lastTryAt.map { Double(now - $0) >= cfg.urgentRefresh } ?? true }
    }

    /// Reads DNS when `due` says so (called under `lock`). One thread reads at a time; the others go on with
    /// the list they have instead of queueing behind a slow lookup, and wait for the read only when they have
    /// none.
    private func read(_ due: (Int64) -> Bool) -> NodeList? {
        let now = clock()
        lock.lock()
        if !due(now) { defer { lock.unlock() }; return usable(now) }
        lock.unlock()
        if !reading.try() {
            lock.lock()
            let have = usable(now)
            lock.unlock()
            if let have = have { return have }
            reading.lock()
            reading.unlock()
            lock.lock(); defer { lock.unlock() }
            return usable(clock())
        }
        defer { reading.unlock() }
        lock.lock()
        if !due(now) { defer { lock.unlock() }; return usable(now) } // another thread has just read
        lastTryAt = now
        lock.unlock()
        return fetch(now)
    }

    /// The names the last good list pointed to come first; the ones built into the app are the fallback.
    private func names() -> [String] {
        var seen = Set<String>()
        return ((nextNames?.names ?? current?.next ?? []) + [cfg.name] + cfg.fallbackNames).filter { seen.insert($0).inserted }
    }

    /// For tests: the names the directory would read from, in order.
    func namesForTest() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return names()
    }

    private func usable(_ now: Int64) -> NodeList? {
        if let c = current, now <= c.exp { return c }
        return nil
    }

    private func fetch(_ now: Int64) -> NodeList? {
        lock.lock()
        let candidates = names()
        let floor = max(floorIat, current?.iat ?? 0)
        lock.unlock()
        var found: NodeList?
        var from = ""
        for n in candidates {
            let recs = queryTxt?(n) ?? Resolvers.query(cfg: cfg, name: n, minIat: floor)
            guard let f = try? ListVerifier.parse(recs, publicKeyB64: cfg.publicKey, now: now,
                                                  listKeyB64: cfg.listKey) else { continue }
            if f.iat < floor { continue } // stale copy at this name; try the next
            found = f
            from = n
            break
        }
        lock.lock()
        guard let fresh = found else {
            nextTryAt = now + Int64(cfg.retryInterval)
            defer { lock.unlock() }
            return usable(now)
        }
        current = fresh
        floorIat = fresh.iat
        nextTryAt = now + Int64(cfg.refreshInterval)
        lock.unlock()
        save()
        // a compact list leaves the names to read next time to a record of its own, read in the background
        if fresh.records.count == 1 && Compact.looksCompact(fresh.records[0]) { fetchNext(from, now: now) }
        return fresh
    }

    private func save() {
        lock.lock()
        let recs = (current?.records ?? []) + (nextNames?.records ?? [])
        lock.unlock()
        if !recs.isEmpty { cfg.store?.save(recs) }
    }

    /// Reads dw2.<name> without holding anyone up; a newer valid answer replaces the names kept.
    private func fetchNext(_ name: String, now: Int64) {
        lock.lock()
        if nextBusy { lock.unlock(); return }
        nextBusy = true
        let minIat = nextNames?.iat ?? 0
        lock.unlock()
        Blocking.run("gamec.shield.next") { [self] in
            let at = Compact.nextName(name)
            let recs = queryTxt?(at) ?? Resolvers.queryNext(cfg: cfg, name: at, minIat: minIat)
            let nn = try? NextVerifier.parse(recs, publicKeyB64: cfg.publicKey, now: now, listKeyB64: cfg.listKey)
            lock.lock()
            var newer = false
            if let nn = nn, nn.iat >= (nextNames?.iat ?? 0) {
                nextNames = nn
                newer = true
            }
            nextBusy = false
            lock.unlock()
            if newer { save() }
        }
    }
}
