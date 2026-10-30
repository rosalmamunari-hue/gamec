import Foundation

/// Default resolvers. Public so they can be used as default arguments and extended by the app.
public enum DnsDefaults {
    /// JSON DoH endpoints reached by IP address, so no prior (possibly poisoned) DNS lookup is needed.
    public static let doh = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve", "https://223.5.5.5/resolve"]
    /// DNS-over-TLS servers on port 853 ("host" or "host:port"), by IP address.
    public static let dot = ["8.8.8.8", "1.1.1.1", "223.5.5.5"]
    /// Plain DNS servers on port 53 ("host" or "host:port"), by IP address.
    public static let do53 = ["8.8.8.8", "1.1.1.1", "223.5.5.5"]
}

/// One way of asking DNS for TXT records. Blocking.
typealias TxtResolver = (_ name: String, _ timeout: TimeInterval) -> [String]
typealias NamedResolver = (label: String, query: TxtResolver)

enum Race {
    /// Starts `tasks` `stagger` seconds apart (task i begins after i * stagger) and returns the first non-nil
    /// result. Returns nil if every task comes back empty or `timeout` passes. Tasks that have not started
    /// when a winner appears are skipped.
    static func first<T>(_ tasks: [() -> T?], stagger: TimeInterval, timeout: TimeInterval) -> T? {
        guard !tasks.isEmpty else { return nil }
        let lock = NSLock()
        var winner: T?
        var finished = 0
        var cancelled = false
        let signal = DispatchSemaphore(value: 0)

        for (i, task) in tasks.enumerated() {
            Blocking.run("gamec.race") {
                if i > 0 { Thread.sleep(forTimeInterval: Double(i) * stagger) }
                lock.lock(); let skip = cancelled; lock.unlock()
                let result = skip ? nil : task()
                lock.lock()
                finished += 1
                if winner == nil, let r = result { winner = r }
                lock.unlock()
                signal.signal()
            }
        }

        let deadline = DispatchTime.now() + timeout
        while signal.wait(timeout: deadline) == .success {
            lock.lock(); let w = winner; let done = finished; lock.unlock()
            if w != nil || done == tasks.count { break }
        }
        lock.lock()
        cancelled = true
        let w = winner
        lock.unlock()
        return w
    }
}

enum Resolvers {
    private static let lock = NSLock()
    private static var _lastWinner = ""
    /// Name of the resolver that answered last, for diagnostics.
    static var lastWinner: String {
        get { lock.lock(); defer { lock.unlock() }; return _lastWinner }
        set { lock.lock(); _lastWinner = newValue; lock.unlock() }
    }

    private static func hostPort(_ s: String, defaultPort: UInt16) -> (String, UInt16) {
        let parts = s.split(separator: ":", maxSplits: 1)
        return (String(parts[0]), parts.count > 1 ? (UInt16(parts[1]) ?? defaultPort) : defaultPort)
    }

    /// DoT, DoH and plain DNS (port 53) interleaved so all three transports start early.
    static func build(_ cfg: DiscoveryConfig) -> [NamedResolver] {
        let dot: [NamedResolver] = cfg.dotServers.map { s in
            let (host, port) = hostPort(s, defaultPort: 853)
            return ("dot:\(s)", { name, timeout in (try? Dot.query(host: host, port: port, name: name, timeout: timeout)) ?? [] })
        }
        let doh: [NamedResolver] = cfg.dohProviders.map { url in
            ("doh:\(url)", { name, timeout in Doh.queryTxt(name: name, providers: [url], timeout: timeout) })
        }
        let do53: [NamedResolver] = cfg.do53Servers.map { s in
            let (host, port) = hostPort(s, defaultPort: 53)
            return ("do53:\(s)", { name, timeout in (try? Do53.query(host: host, port: port, name: name, timeout: timeout)) ?? [] })
        }
        var out: [NamedResolver] = []
        for i in 0..<max(dot.count, doh.count, do53.count) {
            if i < dot.count { out.append(dot[i]) }
            if i < doh.count { out.append(doh[i]) }
            if i < do53.count { out.append(do53[i]) }
        }
        return out
    }

    /// Asks every resolver, staggered, and returns the records of the first one whose answer passes `valid`
    /// (for the node list: a correct signature). A resolver that answers with garbage or a forged list loses.
    static func race(_ resolvers: [NamedResolver], name: String, timeout: TimeInterval, stagger: TimeInterval,
                     valid: @escaping ([String]) -> Bool) -> [String] {
        let tasks: [() -> [String]?] = resolvers.map { r in
            {
                let recs = r.query(name, timeout)
                guard !recs.isEmpty, valid(recs) else { return nil }
                lastWinner = r.label
                return recs
            }
        }
        let overall = timeout + stagger * Double(max(tasks.count - 1, 0))
        return Race.first(tasks, stagger: stagger, timeout: overall) ?? []
    }

    /// A resolver wins only with a list that verifies (with `cfg.listKey`, so sealed lists count) and is not
    /// older than `minIat`, the list already held: a replayed older list cannot crowd out a newer one.
    static func query(cfg: DiscoveryConfig, name: String, minIat: Int64 = 0) -> [String] {
        race(build(cfg), name: name, timeout: cfg.timeout, stagger: cfg.resolverStagger) {
            accepts(cfg: cfg, records: $0, minIat: minIat, now: Int64(Date().timeIntervalSince1970))
        }
    }

    static func accepts(cfg: DiscoveryConfig, records: [String], minIat: Int64, now: Int64) -> Bool {
        guard let l = try? ListVerifier.parse(records, publicKeyB64: cfg.publicKey, now: now,
                                              listKeyB64: cfg.listKey) else { return false }
        return l.iat >= minIat
    }
}
