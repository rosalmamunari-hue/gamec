import Foundation
import Network
import XCTest
@testable import GamecShield

/// DNS wire format, DoT framing and the resolver race; no external network (except the opt-in live test).
final class DnsTests: XCTestCase {
    // MARK: helpers: build DNS responses the way real servers do

    private func u16(_ d: inout Data, _ v: Int) { d.append(UInt8(v >> 8)); d.append(UInt8(v & 0xFF)) }

    private func nameBytes(_ name: String) -> Data {
        var d = Data()
        for l in name.split(separator: ".") { d.append(UInt8(l.count)); d.append(contentsOf: Array(l.utf8)) }
        d.append(0)
        return d
    }

    /// A response to a TXT question; each answer is a list of TXT strings (one record). Answers use a name pointer.
    private func response(id: Int, name: String, answers: [[String]], rcode: Int = 0, qr: Bool = true) -> Data {
        var d = Data()
        u16(&d, id)
        u16(&d, (qr ? 0x8180 : 0x0100) | rcode)
        u16(&d, 1); u16(&d, answers.count); u16(&d, 0); u16(&d, 0)
        d.append(nameBytes(name)); u16(&d, 16); u16(&d, 1)
        for strings in answers {
            d.append(0xC0); d.append(12) // pointer to the question name at offset 12
            u16(&d, 16); u16(&d, 1)
            d.append(contentsOf: [0, 0, 0, 60]) // TTL
            var rd = Data()
            for s in strings { rd.append(UInt8(s.utf8.count)); rd.append(contentsOf: Array(s.utf8)) }
            u16(&d, rd.count); d.append(rd)
        }
        return d
    }

    // MARK: wire format

    func testQueryHasTheExpectedShape() throws {
        let q = [UInt8](try DnsWire.buildQuery(name: "_gs.example.com", id: 0x1234))
        XCTAssertEqual(q[0], 0x12); XCTAssertEqual(q[1], 0x34)
        XCTAssertEqual(q[2], 0x01); XCTAssertEqual(q[3], 0x00) // RD
        XCTAssertEqual(q[5], 1) // one question
        XCTAssertEqual(q[12], 3) // first label "_gs"
        XCTAssertEqual(String(decoding: q[13..<16], as: UTF8.self), "_gs")
        XCTAssertEqual(q[q.count - 3], 16) // type TXT
        XCTAssertEqual(q[q.count - 1], 1) // class IN
    }

    func testOverlongLabelIsRejected() {
        XCTAssertThrowsError(try DnsWire.buildQuery(name: String(repeating: "a", count: 64) + ".com", id: 1))
    }

    func testParsesSeveralRecordsAndJoinsTheStringsOfEachOne() throws {
        let msg = response(id: 7, name: "_gs.example.com", answers: [["1/2:", "abc"], ["2/2:def"]])
        XCTAssertEqual(try DnsWire.parseTxt(msg, expectId: 7), ["1/2:abc", "2/2:def"])
    }

    func testNoSuchNameGivesAnEmptyList() throws {
        XCTAssertEqual(try DnsWire.parseTxt(response(id: 9, name: "x.example", answers: [], rcode: 3), expectId: 9), [])
    }

    func testServerFailureIsAnError() {
        XCTAssertThrowsError(try DnsWire.parseTxt(response(id: 9, name: "x.example", answers: [], rcode: 2), expectId: 9))
    }

    func testAnswerForAnotherQuestionIsRejected() {
        XCTAssertThrowsError(try DnsWire.parseTxt(response(id: 1, name: "x.example", answers: [["v"]]), expectId: 2))
    }

    func testAQueryIsNotAResponse() {
        XCTAssertThrowsError(try DnsWire.parseTxt(response(id: 1, name: "x.example", answers: [["v"]], qr: false), expectId: 1))
    }

    func testTruncatedMessagesNeverReadOutOfBounds() {
        let full = response(id: 3, name: "_gs.example.com", answers: [["hello world"]])
        for cut in 0..<full.count {
            // must either throw or (only when the cut lands after the data) parse; it must never crash
            _ = try? DnsWire.parseTxt(full.prefix(cut), expectId: 3)
        }
        XCTAssertThrowsError(try DnsWire.parseTxt(full.prefix(full.count - 5), expectId: 3))
    }

    // MARK: DoT framing over a plain loopback connection (TLS itself is covered by the opt-in live test)

    private final class DnsTcpServer {
        let listener: NWListener
        private let q = DispatchQueue(label: "test.dns")
        private var conns: [NWConnection] = []
        var port: UInt16 = 0

        init(respond: @escaping (Data) -> Data?) throws {
            listener = try NWListener(using: .tcp, on: .any)
            let ready = DispatchSemaphore(value: 0)
            listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
            listener.newConnectionHandler = { [weak self] c in
                guard let self = self else { return }
                self.conns.append(c)
                c.start(queue: self.q)
                c.receive(minimumIncompleteLength: 2, maximumLength: 4096) { data, _, _, _ in
                    guard let data = data, data.count >= 2 else { return c.cancel() }
                    let query = data.dropFirst(2)
                    if let r = respond(Data(query)) {
                        let framed = Data([UInt8(r.count >> 8), UInt8(r.count & 0xFF)]) + r
                        c.send(content: framed, completion: .contentProcessed { _ in c.cancel() })
                    } else {
                        c.cancel()
                    }
                }
            }
            listener.start(queue: q)
            _ = ready.wait(timeout: .now() + 3)
            port = listener.port!.rawValue
        }

        func stop() { listener.cancel(); conns.forEach { $0.cancel() } }
    }

    private func plain(_ s: DnsTcpServer) -> Dot.Connect {
        return { _, _, _, queue, done in
            let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: s.port)!, using: .tcp)
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

    private func queryID(_ q: Data) -> Int { Int(q[q.startIndex]) << 8 | Int(q[q.startIndex + 1]) }

    func testDotRoundTrip() throws {
        let s = try DnsTcpServer { q in self.response(id: self.queryID(q), name: "_gs.example.com", answers: [["1/1:payload"]]) }
        defer { s.stop() }
        XCTAssertEqual(try Dot.query(host: "127.0.0.1", name: "_gs.example.com", timeout: 2, connect: plain(s)), ["1/1:payload"])
    }

    func testDotServerThatHangsUpIsAnError() throws {
        let s = try DnsTcpServer { _ in nil }
        defer { s.stop() }
        XCTAssertThrowsError(try Dot.query(host: "127.0.0.1", name: "_gs.example.com", timeout: 1, connect: plain(s)))
    }

    func testDotServerAnsweringTheWrongQuestionIsRefused() throws {
        let s = try DnsTcpServer { _ in self.response(id: 0x7777, name: "_gs.example.com", answers: [["forged"]]) }
        defer { s.stop() }
        XCTAssertThrowsError(try Dot.query(host: "127.0.0.1", name: "_gs.example.com", timeout: 1, connect: plain(s)))
    }

    // MARK: the race

    func testTheFirstUsableAnswerWinsEvenIfEarlierResolversAreSlowOrBroken() {
        let resolvers: [NamedResolver] = [
            ("dot:blocked", { _, _ in Thread.sleep(forTimeInterval: 3); return [] }),
            ("doh:broken", { _, _ in [] }),
            ("doh:good", { _, _ in ["1/1:ok"] }),
        ]
        let t0 = Date()
        let got = Resolvers.race(resolvers, name: "n", timeout: 5, stagger: 0.05) { !$0.isEmpty }
        XCTAssertEqual(got, ["1/1:ok"])
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.5, "must not wait for the slow resolver")
        XCTAssertEqual(Resolvers.lastWinner, "doh:good")
    }

    func testAResolverWithAForgedAnswerDoesNotWin() {
        let resolvers: [NamedResolver] = [
            ("dot:evil", { _, _ in ["forged"] }),
            ("doh:honest", { _, _ in Thread.sleep(forTimeInterval: 0.3); return ["genuine"] }),
        ]
        let got = Resolvers.race(resolvers, name: "n", timeout: 3, stagger: 0.02) { $0 == ["genuine"] }
        XCTAssertEqual(got, ["genuine"])
    }

    func testLaterResolversAreNotStartedOnceTheFirstHasWon() {
        let lock = NSLock()
        var started = 0
        let count: TxtResolver = { _, _ in lock.lock(); started += 1; lock.unlock(); return ["x"] }
        let resolvers: [NamedResolver] = [("a", count), ("b", count), ("c", count)]
        _ = Resolvers.race(resolvers, name: "n", timeout: 3, stagger: 0.4) { _ in true }
        Thread.sleep(forTimeInterval: 1.2)
        lock.lock(); defer { lock.unlock() }
        XCTAssertEqual(started, 1, "the stagger exists so a fast first answer avoids the extra queries")
    }

    func testNothingUsableMeansEmpty() {
        let resolvers: [NamedResolver] = [("a", { _, _ in [] }), ("b", { _, _ in [] })]
        XCTAssertEqual(Resolvers.race(resolvers, name: "n", timeout: 1, stagger: 0.01) { _ in true }, [])
    }

    func testGiveUpAtTheTimeout() {
        let resolvers: [NamedResolver] = [("slow", { _, _ in Thread.sleep(forTimeInterval: 5); return ["late"] })]
        let t0 = Date()
        XCTAssertEqual(Resolvers.race(resolvers, name: "n", timeout: 0.5, stagger: 0) { _ in true }, [])
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.5)
    }

    func testResolversAreInterleavedDotFirst() throws {
        let cfg = try DiscoveryConfig(name: "n", publicKey: "k", deviceId: "device-1234567890abcdef",
                                      dohProviders: ["https://doh1/x", "https://doh2/x"],
                                      dotServers: ["1.1.1.1", "9.9.9.9:8853"])
        XCTAssertEqual(Resolvers.build(cfg).map { $0.label },
                       ["dot:1.1.1.1", "doh:https://doh1/x", "dot:9.9.9.9:8853", "doh:https://doh2/x"])
    }

    func testDotCanBeSwitchedOff() throws {
        let cfg = try DiscoveryConfig(name: "n", publicKey: "k", deviceId: "device-1234567890abcdef",
                                      dohProviders: ["https://doh1/x"], dotServers: [])
        XCTAssertEqual(Resolvers.build(cfg).map { $0.label }, ["doh:https://doh1/x"])
    }

    func testAConfigWithNoResolversAtAllIsRejected() {
        XCTAssertThrowsError(try DiscoveryConfig(name: "n", publicKey: "k", deviceId: "device-1234567890abcdef",
                                                 dohProviders: [], dotServers: []))
    }

    // MARK: opt-in live test against the real public resolvers (set GAMEC_TEST_LIVE_NAME)

    func testLiveDotAndDohAgainstRealResolvers() throws {
        let name = ProcessInfo.processInfo.environment["GAMEC_TEST_LIVE_NAME"] ?? ""
        try XCTSkipIf(name.isEmpty, "GAMEC_TEST_LIVE_NAME not set")

        var dotOK = 0, dohOK = 0
        var report: [String] = []
        for server in DnsDefaults.dot {
            do {
                let recs = try Dot.query(host: server, name: name, timeout: 6)
                report.append("dot \(server): \(recs.count) record(s)")
                if !recs.isEmpty { dotOK += 1 }
            } catch {
                report.append("dot \(server) FAILED: \(error)")
            }
        }
        for url in DnsDefaults.doh {
            let recs = Doh.queryTxt(name: name, providers: [url], timeout: 6)
            report.append("doh \(url): \(recs.count) record(s)")
            if !recs.isEmpty { dohOK += 1 }
        }
        print("LIVE DNS:\n" + report.joined(separator: "\n"))
        XCTAssertGreaterThan(dotOK, 0, "no DoT server worked with the system TLS stack:\n" + report.joined(separator: "\n"))
        XCTAssertGreaterThan(dohOK, 0, "no DoH endpoint worked by IP address:\n" + report.joined(separator: "\n"))
    }
}
