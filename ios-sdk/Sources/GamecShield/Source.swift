import Foundation

/// Where the current node list and a valid token come from. Hides which of the three modes is in use.
protocol Source {
    /// The nodes to use right now, or nil if none are known. May refresh them (blocking).
    func nodes() -> [Node]?
    /// Every known node just failed: look for a newer list now, if this source can (rate limited).
    func refreshNow()
    /// A token valid right now; `ordered` are the nodes to ask, best first, if the source must request one.
    func token(ordered: [Node]) -> String?
}

final class StaticSource: Source {
    private let fixed: [Node]
    private let provider: () -> String
    init(nodes: [Node], provider: @escaping () -> String) {
        fixed = nodes
        self.provider = provider
    }
    func nodes() -> [Node]? { fixed }
    func refreshNow() {}
    func token(ordered: [Node]) -> String? { provider() }
}

final class ControlSource: Source {
    private let sessions: SessionManager
    init(_ cfg: ControlConfig) { sessions = SessionManager(cfg: cfg) }
    func nodes() -> [Node]? { sessions.get()?.nodes }
    func refreshNow() {}
    func token(ordered: [Node]) -> String? { sessions.get()?.token }
}

final class DiscoverySource: Source {
    private let directory: NodeDirectory
    private let tokens: TokenManager
    /// Asking a node for a token is a connection to it, so it gets the same timeout as a connection.
    init(_ cfg: DiscoveryConfig, connectTimeout: TimeInterval) {
        directory = NodeDirectory(cfg: cfg)
        tokens = TokenManager(deviceId: cfg.deviceId, margin: Int64(cfg.tokenMargin), timeout: connectTimeout)
    }
    func nodes() -> [Node]? { directory.get()?.nodes }
    func refreshNow() { _ = directory.refreshNow() }
    func token(ordered: [Node]) -> String? { tokens.get(ordered) }
}

extension ShieldConfig {
    func makeSource() -> Source {
        if let d = discovery { return DiscoverySource(d, connectTimeout: connectTimeout) }
        if let c = control { return ControlSource(c) }
        return StaticSource(nodes: nodes, provider: tokenProvider!)
    }
}
