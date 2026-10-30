import Foundation
import Network

/// Local TCP proxy. The game connects to 127.0.0.1:<port returned by start()>; each connection is relayed
/// over pinned TLS 1.3 to the fastest healthy edge node, which forwards to the hidden origin.
///
///     let shield = ShieldClient(config: ShieldConfig(nodes: nodes, tokenProvider: { cachedToken }))
///     let port = try shield.start()
///     // point the game socket at 127.0.0.1:port
public final class ShieldClient {
    private let cfg: ShieldConfig
    private let selector: NodeSelector
    private let sessions: SessionManager?
    private let queue = DispatchQueue(label: "gamec.shield")
    private var listener: NWListener?
    private var probeTimer: DispatchSourceTimer?

    public init(config: ShieldConfig) {
        cfg = config
        selector = NodeSelector(nodes: config.nodes, cooldown: config.failCooldown)
        sessions = config.control.map { SessionManager(cfg: $0) }
    }

    /// Refreshes the session (blocking, so never on the shield queue) and re-measures every node.
    private func refreshAndProbe() {
        DispatchQueue.global().async { [self] in
            if let s = sessions?.get() { selector.update(s.nodes) }
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

        refreshAndProbe()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + cfg.reprobeInterval, repeating: cfg.reprobeInterval)
        t.setEventHandler { [weak self] in self?.refreshAndProbe() }
        t.resume()
        probeTimer = t
        return port
    }

    public func stop() {
        probeTimer?.cancel()
        listener?.cancel()
    }

    private func accept(_ local: NWConnection) {
        local.start(queue: queue)
        // Fetching a session or calling tokenProvider may block, so keep it off the shield queue.
        DispatchQueue.global().async { [self] in
            let token: Data
            if let sessions = sessions {
                guard let s = sessions.get() else {
                    queue.async { local.cancel() }
                    return
                }
                selector.update(s.nodes)
                token = Data(s.token.utf8)
            } else {
                token = Data(cfg.tokenProvider!().utf8)
            }
            queue.async { self.openUpstream(nodes: self.selector.ordered(), token: token, local: local) }
        }
    }

    /// Tries nodes in order; the first one that completes TLS and takes the token frame wins.
    private func openUpstream(nodes: [Node], token: Data, local: NWConnection) {
        guard let node = nodes.first else { local.cancel(); return }
        let rest = Array(nodes.dropFirst())
        PinnedTLS.connect(node, timeout: cfg.connectTimeout, queue: queue) { [self] up in
            guard let up = up else {
                selector.recordFailure(node)
                openUpstream(nodes: rest, token: token, local: local)
                return
            }
            let frame = Data([UInt8(token.count >> 8), UInt8(token.count & 0xff)]) + token
            up.send(content: frame, completion: .contentProcessed { [self] err in
                if err != nil {
                    selector.recordFailure(node)
                    up.cancel()
                    openUpstream(nodes: rest, token: token, local: local)
                    return
                }
                bridge(local, up)
            })
        }
    }

    private func bridge(_ a: NWConnection, _ b: NWConnection) {
        var closed = false
        let close = {
            if closed { return }
            closed = true
            a.cancel()
            b.cancel()
        }
        pump(a, b, close)
        pump(b, a, close)
    }

    private func pump(_ from: NWConnection, _ to: NWConnection, _ close: @escaping () -> Void) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [self] data, _, isComplete, error in
            if let data = data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { err in
                    if err != nil || isComplete || error != nil {
                        close()
                    } else {
                        self.pump(from, to, close)
                    }
                })
            } else if isComplete || error != nil {
                close()
            } else {
                pump(from, to, close)
            }
        }
    }
}
