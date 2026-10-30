import Foundation
import Network

/// Local TCP proxy. The game connects to 127.0.0.1:<port returned by start()>; each connection is relayed
/// over pinned TLS 1.3 to the fastest healthy edge node, which forwards to the hidden origin.
///
///     let shield = ShieldClient(config: ShieldConfig(nodes: nodes, tokenProvider: { cachedToken }))
///     let port = try shield.start()
///     // point the game socket at 127.0.0.1:port
///
/// Reconnecting: if no node can be reached the SDK keeps retrying for `connectRetryWindow` with the game's
/// socket held open. A connection that was established and then dies is closed, which makes the game
/// reconnect; that reconnect picks a healthy node. A connection cannot be moved to another node while it
/// lives, because the node-to-origin leg dies with the node.
public final class ShieldClient {
    /// Opens one upstream connection to a node and authenticates it with the token; calls back with nil on
    /// failure. Must always call back. The connection must be started on the given queue.
    typealias Connector = (Node, Data, TimeInterval, DispatchQueue, @escaping (NWConnection?) -> Void) -> Void

    /// Pinned TLS 1.3, then the token frame (2-byte length + token).
    static let tlsConnector: Connector = { node, token, timeout, queue, done in
        PinnedTLS.connect(node, timeout: timeout, queue: queue) { conn in
            guard let conn = conn else { return done(nil) }
            let frame = Data([UInt8(token.count >> 8), UInt8(token.count & 0xff)]) + token
            conn.send(content: frame, completion: .contentProcessed { err in
                if err != nil {
                    conn.cancel()
                    done(nil)
                } else {
                    done(conn)
                }
            })
        }
    }

    /// One relayed connection. Only touched on `queue`.
    private final class Conn {
        let local: NWConnection
        let upstream: NWConnection
        /// When data was first sent upstream with nothing received since; nil = nothing outstanding.
        var pendingSince: Date?
        var closed = false
        init(local: NWConnection, upstream: NWConnection) {
            self.local = local
            self.upstream = upstream
        }
    }

    private let cfg: ShieldConfig
    private let selector: NodeSelector
    private let source: Source
    private let connector: Connector
    private let queue = DispatchQueue(label: "gamec.shield")
    private var listener: NWListener?
    private var probeTimer: DispatchSourceTimer?
    private var watchdogTimer: DispatchSourceTimer?
    private var live: [Conn] = [] // queue only
    private let runLock = NSLock()
    private var runningFlag = false

    public convenience init(config: ShieldConfig) {
        self.init(config: config, source: config.makeSource(), connector: ShieldClient.tlsConnector)
    }

    init(config: ShieldConfig, source: Source, connector: @escaping Connector) {
        cfg = config
        self.source = source
        self.connector = connector
        selector = NodeSelector(nodes: config.nodes, cooldown: config.failCooldown)
    }

    private var running: Bool {
        get { runLock.lock(); defer { runLock.unlock() }; return runningFlag }
        set { runLock.lock(); runningFlag = newValue; runLock.unlock() }
    }

    /// Refreshes the session (blocking, so never on the shield queue) and re-measures every node.
    private func refreshAndProbe() {
        DispatchQueue.global().async { [self] in
            if let n = source.nodes() { selector.update(n) }
            selector.probeAll(timeout: cfg.connectTimeout, queue: queue)
        }
    }

    /// Starts the loopback listener and returns the local port.
    public func start() throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        let l = try NWListener(using: params, on: cfg.localPort == 0 ? .any : NWEndpoint.Port(rawValue: cfg.localPort)!)

        let ready = DispatchSemaphore(value: 0)
        var failure: NWError?
        l.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let e): failure = e; ready.signal()
            default: break
            }
        }
        l.newConnectionHandler = { [weak self] local in self?.accept(local) }
        l.start(queue: queue)
        _ = ready.wait(timeout: .now() + 3)
        if let e = failure { throw e }
        guard let port = l.port?.rawValue else { throw NWError.posix(.EADDRNOTAVAIL) }
        listener = l
        running = true

        refreshAndProbe()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + cfg.reprobeInterval, repeating: cfg.reprobeInterval)
        t.setEventHandler { [weak self] in self?.refreshAndProbe() }
        t.resume()
        probeTimer = t

        let w = DispatchSource.makeTimerSource(queue: queue)
        w.schedule(deadline: .now() + 0.5, repeating: 0.5)
        w.setEventHandler { [weak self] in self?.watchdog() }
        w.resume()
        watchdogTimer = w
        return port
    }

    public func stop() {
        running = false
        probeTimer?.cancel()
        watchdogTimer?.cancel()
        listener?.cancel()
        queue.async { [self] in
            for c in live { close(c) }
        }
    }

    /// Closes connections that were sent data but heard nothing back for too long. Runs on `queue`.
    private func watchdog() {
        let limit = cfg.deadAfterUnanswered
        guard limit > 0 else { return }
        let now = Date()
        for c in live {
            if let since = c.pendingSince, now.timeIntervalSince(since) > limit {
                cfg.listener?.shieldConnectionLost(reason: "no response for \(Int(now.timeIntervalSince(since)))s")
                close(c)
            }
        }
    }

    private func close(_ c: Conn) {
        guard !c.closed else { return }
        c.closed = true
        live.removeAll { $0 === c }
        c.local.cancel()
        c.upstream.cancel()
    }

    private func accept(_ local: NWConnection) {
        local.start(queue: queue)
        // Looking up the session and retrying can block for a while, so keep it off the shield queue.
        DispatchQueue.global().async { [self] in
            guard let up = openUpstream() else {
                queue.async { local.cancel() }
                return
            }
            queue.async { [self] in
                guard running else {
                    local.cancel()
                    up.cancel()
                    return
                }
                bridge(local, up)
            }
        }
    }

    /// One round: current nodes, a token, then each node in order. Blocking.
    private func tryOnce() -> NWConnection? {
        if source.nodes() == nil { source.refreshNow() }
        guard let nodes = source.nodes() else { return nil }
        selector.update(nodes)
        guard let tokenString = source.token(ordered: selector.ordered()) else { return nil }
        let token = Data(tokenString.utf8)
        for node in selector.ordered() {
            let done = DispatchSemaphore(value: 0)
            var result: NWConnection?
            connector(node, token, cfg.connectTimeout, queue) { conn in
                result = conn
                done.signal()
            }
            done.wait()
            if let conn = result {
                cfg.listener?.shieldConnected(node: "\(node.host):\(node.port)")
                return conn
            }
            selector.recordFailure(node)
        }
        source.refreshNow() // every node failed: the next round may already have a newer list
        return nil
    }

    /// Rounds of `tryOnce` with exponential backoff and jitter until one works or the retry window ends.
    /// Nodes and token are looked up again every round, so a refreshed node list is picked up.
    private func openUpstream() -> NWConnection? {
        let start = Date()
        var backoff = cfg.retryMin
        var attempt = 0
        while running {
            if let conn = tryOnce() { return conn }
            let left = cfg.connectRetryWindow - Date().timeIntervalSince(start)
            if left <= 0 { break }
            attempt += 1
            cfg.listener?.shieldRetrying(attempt: attempt)
            let jitter = Double.random(in: 0...(backoff / 2))
            Thread.sleep(forTimeInterval: min(backoff + jitter, left))
            backoff = min(backoff * 2, cfg.retryMax)
        }
        if running { cfg.listener?.shieldConnectFailed() }
        return nil
    }

    private func bridge(_ local: NWConnection, _ upstream: NWConnection) {
        let c = Conn(local: local, upstream: upstream)
        live.append(c)
        pump(from: local, to: upstream, c, outbound: true)
        pump(from: upstream, to: local, c, outbound: false)
    }

    private func pump(from: NWConnection, to: NWConnection, _ c: Conn, outbound: Bool) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [self] data, _, isComplete, error in
            if let data = data, !data.isEmpty {
                if !outbound { c.pendingSince = nil }
                to.send(content: data, completion: .contentProcessed { [self] err in
                    if err != nil || isComplete || error != nil {
                        close(c)
                    } else {
                        if outbound && c.pendingSince == nil { c.pendingSince = Date() }
                        pump(from: from, to: to, c, outbound: outbound)
                    }
                })
            } else if isComplete || error != nil {
                close(c)
            } else {
                pump(from: from, to: to, c, outbound: outbound)
            }
        }
    }
}
