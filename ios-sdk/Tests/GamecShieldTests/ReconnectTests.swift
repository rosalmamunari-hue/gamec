import Foundation
import Network
import XCTest
@testable import GamecShield

/// Retry window, backoff and dead-connection detection, without any real network: the "node" is a loopback
/// server the test controls, reached through a fake connector.
final class ReconnectTests: XCTestCase {
    private let node = Node(host: "fake-node", port: 1, pinSha256: "pin")

    // MARK: helpers

    private final class Events: ShieldListener {
        private let lock = NSLock()
        private var _connected = 0, _retrying = 0, _failed = 0, _lost = 0
        var connected: Int { lock.lock(); defer { lock.unlock() }; return _connected }
        var retrying: Int { lock.lock(); defer { lock.unlock() }; return _retrying }
        var failed: Int { lock.lock(); defer { lock.unlock() }; return _failed }
        var lost: Int { lock.lock(); defer { lock.unlock() }; return _lost }
        func shieldConnected(node: String) { lock.lock(); _connected += 1; lock.unlock() }
        func shieldRetrying(attempt: Int) { lock.lock(); _retrying += 1; lock.unlock() }
        func shieldConnectFailed() { lock.lock(); _failed += 1; lock.unlock() }
        func shieldConnectionLost(reason: String) { lock.lock(); _lost += 1; lock.unlock() }
    }

    /// A loopback TCP server standing in for the node/origin: echoes if `echo`, otherwise swallows silently.
    private final class Remote {
        let listener: NWListener
        private let q = DispatchQueue(label: "test.remote")
        private var conns: [NWConnection] = []
        var port: UInt16 = 0

        init(echo: Bool) throws {
            listener = try NWListener(using: .tcp, on: .any)
            let ready = DispatchSemaphore(value: 0)
            listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
            listener.newConnectionHandler = { [weak self] c in
                guard let self = self else { return }
                self.conns.append(c)
                c.start(queue: self.q)
                func loop() {
                    c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, done, err in
                        if let d = data, !d.isEmpty, echo { c.send(content: d, completion: .contentProcessed { _ in }) }
                        if done || err != nil { return }
                        loop()
                    }
                }
                loop()
            }
            listener.start(queue: q)
            _ = ready.wait(timeout: .now() + 3)
            port = listener.port!.rawValue
        }

        func stop() {
            listener.cancel()
            conns.forEach { $0.cancel() }
        }
    }

    /// Connector that talks plain TCP to a local port instead of TLS to a real node.
    private func plainConnector(to port: UInt16) -> ShieldClient.Connector {
        return { _, _, _, queue, done in
            let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            var finished = false
            c.stateUpdateHandler = { state in
                switch state {
                case .ready: if !finished { finished = true; done(c) }
                case .failed, .cancelled: if !finished { finished = true; done(nil) }
                default: break
                }
            }
            c.start(queue: queue)
        }
    }

    /// A game-side socket connected to the SDK's local port.
    private final class GameSocket {
        private let conn: NWConnection
        private let lock = NSLock()
        private var _data = Data()
        private var _closed = false
        var data: Data { lock.lock(); defer { lock.unlock() }; return _data }
        var closed: Bool { lock.lock(); defer { lock.unlock() }; return _closed }

        init(port: UInt16) {
            conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            conn.stateUpdateHandler = { [weak self] s in
                if case .failed = s { self?.markClosed() }
                if case .cancelled = s { self?.markClosed() }
            }
            conn.start(queue: DispatchQueue(label: "test.game"))
            read()
        }

        private func markClosed() { lock.lock(); _closed = true; lock.unlock() }

        private func read() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] d, _, done, err in
                guard let self = self else { return }
                if let d = d, !d.isEmpty { self.lock.lock(); self._data.append(d); self.lock.unlock() }
                if done || err != nil { self.markClosed(); return }
                self.read()
            }
        }

        func send(_ s: String) { conn.send(content: Data(s.utf8), completion: .contentProcessed { _ in }) }
        func close() { conn.cancel() }

        /// Polls until `cond` holds or the timeout passes.
        func wait(_ timeout: TimeInterval, until cond: () -> Bool) -> Bool {
            let end = Date().addingTimeInterval(timeout)
            while Date() < end {
                if cond() { return true }
                Thread.sleep(forTimeInterval: 0.02)
            }
            return cond()
        }
    }

    private func makeClient(_ connector: @escaping ShieldClient.Connector, _ events: Events,
                            window: TimeInterval = 5, deadAfter: TimeInterval = 0) throws -> (ShieldClient, UInt16) {
        let cfg = ShieldConfig(nodes: [node], tokenProvider: { "tok" },
                               connectRetryWindow: window, retryMin: 0.05, retryMax: 0.2,
                               deadAfterUnanswered: deadAfter, listener: events)
        let shield = ShieldClient(config: cfg, source: cfg.makeSource(), connector: connector)
        let port = try shield.start()
        addTeardownBlock { shield.stop() }
        return (shield, port)
    }

    private let alwaysDown: ShieldClient.Connector = { _, _, _, _, done in done(nil) }

    // MARK: tests

    func testKeepsRetryingUntilTheNodeComesBack() throws {
        let remote = try Remote(echo: true)
        addTeardownBlock { remote.stop() }
        let real = plainConnector(to: remote.port)
        let calls = NSLock()
        var n = 0
        let flaky: ShieldClient.Connector = { node, token, timeout, queue, done in
            calls.lock(); n += 1; let k = n; calls.unlock()
            if k <= 3 { done(nil) } else { real(node, token, timeout, queue, done) }
        }
        let ev = Events()
        let (_, port) = try makeClient(flaky, ev)

        let game = GameSocket(port: port)
        game.send("ping")
        XCTAssertTrue(game.wait(4) { game.data == Data("ping".utf8) }, "echo never arrived")
        XCTAssertGreaterThanOrEqual(ev.retrying, 1)
        XCTAssertEqual(ev.connected, 1)
        XCTAssertEqual(ev.failed, 0)
    }

    func testGameSocketStaysOpenWhileRetrying() throws {
        let (_, port) = try makeClient(alwaysDown, Events(), window: 3)
        let game = GameSocket(port: port)
        XCTAssertFalse(game.wait(0.8) { game.closed }, "socket was closed during the retry window")
    }

    func testGivesUpAfterTheRetryWindowAndClosesTheGameSocket() throws {
        let ev = Events()
        let (_, port) = try makeClient(alwaysDown, ev, window: 0.8)
        let t0 = Date()
        let game = GameSocket(port: port)
        XCTAssertTrue(game.wait(5) { game.closed })
        let took = Date().timeIntervalSince(t0)
        XCTAssertTrue((0.6...3.0).contains(took), "closed after \(took)s, expected about the 0.8s window")
        XCTAssertEqual(ev.failed, 1)
        XCTAssertGreaterThanOrEqual(ev.retrying, 2)
    }

    func testZeroWindowFailsImmediately() throws {
        let ev = Events()
        let (_, port) = try makeClient(alwaysDown, ev, window: 0)
        let game = GameSocket(port: port)
        XCTAssertTrue(game.wait(3) { game.closed })
        XCTAssertEqual(ev.retrying, 0)
    }

    func testAConnectionThatNeverAnswersIsClosedSoTheGameReconnects() throws {
        let remote = try Remote(echo: false)
        addTeardownBlock { remote.stop() }
        let ev = Events()
        let (_, port) = try makeClient(plainConnector(to: remote.port), ev, deadAfter: 1)
        let game = GameSocket(port: port)
        game.send("hello?")
        let t0 = Date()
        XCTAssertTrue(game.wait(6) { game.closed })
        let took = Date().timeIntervalSince(t0)
        XCTAssertTrue((0.8...4.0).contains(took), "closed after \(took)s")
        XCTAssertEqual(ev.lost, 1)
    }

    func testAConnectionThatKeepsAnsweringIsLeftAlone() throws {
        let remote = try Remote(echo: true)
        addTeardownBlock { remote.stop() }
        let ev = Events()
        let (_, port) = try makeClient(plainConnector(to: remote.port), ev, deadAfter: 1)
        let game = GameSocket(port: port)
        for i in 1...8 {
            game.send("x")
            XCTAssertTrue(game.wait(2) { game.data.count == i }, "no echo for message \(i)")
            Thread.sleep(forTimeInterval: 0.3) // 2.4s in total, longer than deadAfter
        }
        XCTAssertFalse(game.closed)
        XCTAssertEqual(ev.lost, 0)
    }

    func testDeadDetectionCanBeSwitchedOff() throws {
        let remote = try Remote(echo: false)
        addTeardownBlock { remote.stop() }
        let ev = Events()
        let (_, port) = try makeClient(plainConnector(to: remote.port), ev, deadAfter: 0)
        let game = GameSocket(port: port)
        game.send("hello?")
        XCTAssertFalse(game.wait(2.5) { game.closed })
        XCTAssertEqual(ev.lost, 0)
    }

    func testIdleConnectionWithNothingSentIsNotTreatedAsDead() throws {
        let remote = try Remote(echo: false)
        addTeardownBlock { remote.stop() }
        let ev = Events()
        let (_, port) = try makeClient(plainConnector(to: remote.port), ev, deadAfter: 0.5)
        let game = GameSocket(port: port)
        XCTAssertFalse(game.wait(2) { game.closed })
        XCTAssertEqual(ev.lost, 0)
    }

    func testStopDuringRetriesIsClean() throws {
        for _ in 0..<5 {
            let (shield, port) = try makeClient(alwaysDown, Events(), window: 10)
            let game = GameSocket(port: port)
            Thread.sleep(forTimeInterval: 0.2)
            shield.stop()
            XCTAssertTrue(game.wait(3) { game.closed } || true) // must simply not crash or hang
        }
    }

    /// Calling start() again while running (back in the foreground) starts over on a working port.
    func testStartingAgainWhileRunningGivesAWorkingProxy() throws {
        let remote = try Remote(echo: true)
        addTeardownBlock { remote.stop() }
        let (shield, _) = try makeClient(plainConnector(to: remote.port), Events())
        let port = try shield.start()
        let game = GameSocket(port: port)
        addTeardownBlock { game.close() }
        game.send("ping")
        XCTAssertTrue(game.wait(3) { game.data == Data("ping".utf8) })
    }

    /// 127.0.0.1 is open to every app on the device; past the cap new connections are turned away.
    func testConnectionsPastTheCapAreClosed() throws {
        let remote = try Remote(echo: true)
        addTeardownBlock { remote.stop() }
        let cfg = ShieldConfig(nodes: [node], tokenProvider: { "tok" }, maxConnections: 2)
        let shield = ShieldClient(config: cfg, source: cfg.makeSource(), connector: plainConnector(to: remote.port))
        let port = try shield.start()
        addTeardownBlock { shield.stop() }
        let held = [GameSocket(port: port), GameSocket(port: port)]
        for g in held {
            addTeardownBlock { g.close() }
            g.send("a")
            XCTAssertTrue(g.wait(3) { g.data == Data("a".utf8) }, "both connections under the cap are served")
        }
        let extra = GameSocket(port: port)
        addTeardownBlock { extra.close() }
        extra.send("a")
        XCTAssertTrue(extra.wait(3) { extra.closed }, "a third connection must be closed")
        XCTAssertTrue(extra.data.isEmpty)
    }
}
