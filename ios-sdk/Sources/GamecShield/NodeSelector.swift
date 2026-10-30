import Foundation
import Network

/// Tracks measured latency per node and temporarily benches nodes that fail. The node set can change at runtime.
final class NodeSelector {
    private var nodes: [Node]
    private let cooldown: TimeInterval
    private let lock = NSLock()
    private var rtt: [Node: TimeInterval] = [:]
    private var benchedUntil: [Node: Date] = [:]

    init(nodes: [Node], cooldown: TimeInterval) {
        self.nodes = nodes
        self.cooldown = cooldown
    }

    func update(_ newNodes: [Node]) {
        lock.lock(); defer { lock.unlock() }
        guard newNodes != nodes else { return }
        nodes = newNodes
        let keep = Set(newNodes)
        rtt = rtt.filter { keep.contains($0.key) }
        benchedUntil = benchedUntil.filter { keep.contains($0.key) }
    }

    func recordRtt(_ n: Node, _ seconds: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        rtt[n] = seconds
        benchedUntil[n] = nil
    }

    func recordFailure(_ n: Node) {
        lock.lock(); defer { lock.unlock() }
        benchedUntil[n] = Date().addingTimeInterval(cooldown)
        rtt[n] = nil
    }

    /// Healthy nodes fastest first (unmeasured after measured); benched nodes last, as a final resort.
    func ordered() -> [Node] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let benched = nodes.filter { (benchedUntil[$0] ?? .distantPast) > now }
        let ok = nodes.filter { (benchedUntil[$0] ?? .distantPast) <= now }
            .sorted { (rtt[$0] ?? .infinity) < (rtt[$1] ?? .infinity) }
        return ok + benched
    }

    private func snapshot() -> [Node] {
        lock.lock(); defer { lock.unlock() }
        return nodes
    }

    /// Measure TLS handshake time to every node in parallel.
    func probeAll(timeout: TimeInterval, queue: DispatchQueue) {
        for node in snapshot() {
            let t0 = Date()
            PinnedTLS.connect(node, timeout: timeout, queue: queue) { [self] conn in
                if let conn = conn {
                    recordRtt(node, Date().timeIntervalSince(t0))
                    conn.cancel()
                } else {
                    recordFailure(node)
                }
            }
        }
    }
}
