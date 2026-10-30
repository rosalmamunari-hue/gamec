import CryptoKit
import Foundation
import XCTest
@testable import GamecShield

/// Pure tests for the DNS discovery path; no network, no edge node.
final class DiscoveryTests: XCTestCase {
    private func nodes(_ n: Int) -> [Node] {
        (1...n).map { Node(host: "10.0.0.\($0)", port: 30800, pinSha256: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg=") }
    }

    private func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// Same format as edge/cmd/signlist.
    private func records(_ key: P256.Signing.PrivateKey, _ nodes: [Node], iat: Int64 = 100, exp: Int64 = 10_000,
                         chunk: Int = 200) throws -> [String] {
        let list = nodes.map { "{\"h\":\"\($0.host)\",\"p\":\($0.port),\"k\":\"\($0.pinSha256)\"}" }.joined(separator: ",")
        let payload = Data("{\"v\":1,\"iat\":\(iat),\"exp\":\(exp),\"nodes\":[\(list)]}".utf8)
        let sig = try key.signature(for: payload).derRepresentation
        let body = b64url(payload) + "." + b64url(sig)
        var parts: [String] = []
        var rest = Substring(body)
        while !rest.isEmpty {
            parts.append(String(rest.prefix(chunk)))
            rest = rest.dropFirst(chunk)
        }
        if parts.count == 1 { return parts } // a list that fits is one bare record, like the edge tools make
        return parts.enumerated().map { "\($0.offset + 1)/\(parts.count):\($0.element)" }
    }

    private func pub(_ k: P256.Signing.PrivateKey) -> String { k.publicKey.derRepresentation.base64EncodedString() }

    private func cfg(_ k: P256.Signing.PrivateKey, store: ListStore? = nil,
                     refresh: TimeInterval = 600, retry: TimeInterval = 30) throws -> DiscoveryConfig {
        try DiscoveryConfig(name: "_gs.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef",
                            refreshInterval: refresh, retryInterval: retry, store: store)
    }

    // ---- DoH parsing ----

    func testDohJoinsSplitQuotedStrings() throws {
        let json = Data(#"{"Status":0,"Answer":[{"name":"x","type":16,"TTL":60,"data":"\"1/1:a\" \"bcdef\""}]}"#.utf8)
        XCTAssertEqual(try Doh.parse(json), ["1/1:abcdef"])
    }

    func testDohIgnoresOtherRecordTypesAndFailures() throws {
        XCTAssertEqual(try Doh.parse(Data(#"{"Status":3}"#.utf8)), [])
        XCTAssertEqual(try Doh.parse(Data(#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#.utf8)), [])
    }

    func testDohFallsThroughToTheNextProvider() {
        var urls: [URL] = []
        let out = Doh.queryTxt(name: "_gs.example.com", providers: ["http://bad/dns", "http://good/dns"], timeout: 1) { url, _ in
            urls.append(url)
            if url.host == "bad" { throw ShieldError.badResponse }
            return Data(#"{"Status":0,"Answer":[{"type":16,"data":"\"1/1:zz\""}]}"#.utf8)
        }
        XCTAssertEqual(out, ["1/1:zz"])
        XCTAssertEqual(urls.count, 2)
        XCTAssertTrue(urls[1].absoluteString.contains("name=_gs.example.com"))
        XCTAssertTrue(urls[1].absoluteString.contains("type=TXT"))
    }

    func testAShortListIsOneBareRecordAndParses() throws {
        let k = P256.Signing.PrivateKey()
        let recs = try records(k, [Node(host: "10.0.0.1", port: 30800, pinSha256: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg=")], chunk: 100_000)
        XCTAssertEqual(recs.count, 1)
        XCTAssertFalse(recs[0].contains(":"))
        XCTAssertEqual(try ListVerifier.parse(recs + ["v=spf1 -all"], publicKeyB64: pub(k), now: 200).nodes.count, 1)
    }

    func testDohReturnsNothingWhenEveryProviderFails() {
        let out = Doh.queryTxt(name: "x", providers: ["http://a", "http://b"], timeout: 1) { _, _ in throw ShieldError.badResponse }
        XCTAssertTrue(out.isEmpty)
    }

    // ---- signed list ----

    func testValidMultiChunkListParses() throws {
        let k = P256.Signing.PrivateKey()
        let recs = try records(k, nodes(5))
        XCTAssertGreaterThan(recs.count, 1)
        let l = try ListVerifier.parse(recs, publicKeyB64: pub(k), now: 200)
        XCTAssertEqual(l.nodes, nodes(5))
        XCTAssertEqual(l.iat, 100)
    }

    func testRecordOrderDoesNotMatter() throws {
        let k = P256.Signing.PrivateKey()
        let l = try ListVerifier.parse(try records(k, nodes(5)).reversed(), publicKeyB64: pub(k), now: 200)
        XCTAssertEqual(l.nodes.count, 5)
    }

    func testTamperedListIsRejected() throws {
        let k = P256.Signing.PrivateKey()
        var recs = try records(k, nodes(2))
        var chars = Array(recs[0])
        let i = chars.count - 10
        chars[i] = chars[i] == "A" ? "B" : "A"
        recs[0] = String(chars)
        XCTAssertThrowsError(try ListVerifier.parse(recs, publicKeyB64: pub(k), now: 200))
    }

    func testListSignedByAnotherKeyIsRejected() throws {
        let recs = try records(P256.Signing.PrivateKey(), nodes(2))
        XCTAssertThrowsError(try ListVerifier.parse(recs, publicKeyB64: pub(P256.Signing.PrivateKey()), now: 200))
    }

    func testExpiredListIsRejected() throws {
        let k = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try ListVerifier.parse(try records(k, nodes(2), exp: 150), publicKeyB64: pub(k), now: 200))
    }

    func testIncompleteSetIsRejected() throws {
        let k = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try ListVerifier.parse(Array(try records(k, nodes(5)).dropFirst()), publicKeyB64: pub(k), now: 200))
    }

    func testUnrelatedTxtRecordsAreIgnored() throws {
        let k = P256.Signing.PrivateKey()
        let recs = try records(k, nodes(2)) + ["v=spf1 -all", "google-site-verification=abc"]
        XCTAssertEqual(try ListVerifier.parse(recs, publicKeyB64: pub(k), now: 200).nodes.count, 2)
    }

    func testMixedVersionsDuringPropagationPickTheCompleteValidOne() throws {
        let k = P256.Signing.PrivateKey()
        let old = try records(k, nodes(5), iat: 100)
        let fresh = try records(k, nodes(1), iat: 200)
        let l = try ListVerifier.parse(Array(old.dropFirst()) + fresh, publicKeyB64: pub(k), now: 300)
        XCTAssertEqual(l.nodes.count, 1)
        XCTAssertEqual(l.iat, 200)
    }

    // ---- directory ----

    func testDirectoryCachesUntilTheRefreshInterval() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        var queries = 0
        let recs = try records(k, nodes(2), iat: 900, exp: 99_999)
        let d = NodeDirectory(cfg: try cfg(k, refresh: 600), queryTxt: { _ in queries += 1; return recs }, clock: { now })
        XCTAssertNotNil(d.get())
        _ = d.get()
        XCTAssertEqual(queries, 1)
        now = 1599
        _ = d.get()
        XCTAssertEqual(queries, 1)
        now = 1601
        _ = d.get()
        XCTAssertEqual(queries, 2)
    }

    func testDirectoryFallsBackToTheNextNameWhenTheFirstIsDownOrForged() throws {
        let k = P256.Signing.PrivateKey()
        let good = try records(k, nodes(2), iat: 900, exp: 99_999)
        let forged = try records(P256.Signing.PrivateKey(), nodes(1), iat: 900, exp: 99_999)
        var asked: [String] = []
        let c = try DiscoveryConfig(name: "a.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef",
                                    fallbackNames: ["b.example.com", "c.example.com"])
        let d = NodeDirectory(cfg: c, queryTxt: { n in
            asked.append(n)
            switch n { case "a.example.com": return []; case "b.example.com": return forged; default: return good }
        }, clock: { 1000 })
        XCTAssertEqual(d.get()?.nodes.count, 2)
        XCTAssertEqual(asked, ["a.example.com", "b.example.com", "c.example.com"])
    }

    func testDirectoryFailsOnlyWhenEveryNameFails() throws {
        let k = P256.Signing.PrivateKey()
        let c = try DiscoveryConfig(name: "a.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef",
                                    fallbackNames: ["b.example.com"])
        XCTAssertNil(NodeDirectory(cfg: c, queryTxt: { _ in [] }, clock: { 1000 }).get())
    }

    func testRefreshNowReadsAtOnceButNotMoreOftenThanEveryThreeSeconds() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        var queries = 0
        var iat: Int64 = 900
        let d = NodeDirectory(cfg: try cfg(k, refresh: 600), queryTxt: { _ in
            queries += 1
            return (try? self.records(k, self.nodes(2), iat: iat, exp: 99_999)) ?? []
        }, clock: { now })
        _ = d.get()
        XCTAssertEqual(queries, 1)
        now = 1001; iat = 950
        _ = d.refreshNow()
        XCTAssertEqual(queries, 1)
        now = 1003
        XCTAssertEqual(d.refreshNow()?.iat, 950)
        XCTAssertEqual(queries, 2)
        now = 1004
        _ = d.refreshNow()
        XCTAssertEqual(queries, 2)
    }

    func testRefreshNowKeepsTheOldListWhenTheReadFails() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        var down = false
        let good = try records(k, nodes(2), iat: 900, exp: 99_999)
        let d = NodeDirectory(cfg: try cfg(k), queryTxt: { _ in down ? [] : good }, clock: { now })
        _ = d.get()
        down = true
        now = 1010
        XCTAssertEqual(d.refreshNow()?.nodes.count, 2)
    }

    func testDirectoryNeverGoesBackToAnOlderList() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        let newer = try records(k, nodes(2), iat: 900, exp: 99_999)
        let older = try records(k, nodes(1), iat: 450, exp: 99_999)
        var serveOlder = false
        let d = NodeDirectory(cfg: try cfg(k, refresh: 10), queryTxt: { _ in serveOlder ? older : newer }, clock: { now })
        XCTAssertEqual(d.get()?.iat, 900)
        serveOlder = true // an attacker replays an older signed list
        now = 1100
        XCTAssertEqual(d.get()?.iat, 900, "replayed older list must be ignored")
    }

    func testDirectoryKeepsTheLastListWhileDnsIsDownThenGivesUp() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        var down = false
        let recs = try records(k, nodes(2), iat: 900, exp: 2000)
        let d = NodeDirectory(cfg: try cfg(k, refresh: 10, retry: 10), queryTxt: { _ in down ? [] : recs }, clock: { now })
        XCTAssertNotNil(d.get())
        down = true
        now = 1500
        XCTAssertNotNil(d.get(), "stale but unexpired list is still usable")
        now = 2001
        XCTAssertNil(d.get(), "an expired list must not be used")
    }

    func testDirectoryDoesNotHammerDnsAfterAFailure() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 1000
        var queries = 0
        let d = NodeDirectory(cfg: try cfg(k, retry: 30), queryTxt: { _ in queries += 1; return [] }, clock: { now })
        for _ in 0..<5 { _ = d.get() }
        XCTAssertEqual(queries, 1)
        now = 1031
        _ = d.get()
        XCTAssertEqual(queries, 2)
    }

    private final class MemoryStore: ListStore {
        var saved: [String]
        init(_ s: [String] = []) { saved = s }
        func load() -> [String] { saved }
        func save(_ records: [String]) { saved = records }
    }

    func testDirectoryStartsFromTheSavedListWhenDnsIsUnreachable() throws {
        let k = P256.Signing.PrivateKey()
        let store = MemoryStore(try records(k, nodes(2), iat: 900, exp: 99_999))
        let d = NodeDirectory(cfg: try cfg(k, store: store), queryTxt: { _ in [] }, clock: { 1000 })
        XCTAssertEqual(d.get()?.nodes.count, 2)
    }

    func testDirectorySavesEachGoodListToTheStore() throws {
        let k = P256.Signing.PrivateKey()
        let store = MemoryStore()
        let recs = try records(k, nodes(2), exp: 99_999)
        _ = NodeDirectory(cfg: try cfg(k, store: store), queryTxt: { _ in recs }, clock: { 1000 }).get()
        XCTAssertFalse(store.saved.isEmpty)
        XCTAssertTrue(store.saved.allSatisfy { $0.range(of: "^[0-9]{1,3}/[0-9]{1,3}:", options: .regularExpression) != nil })
    }

    // ---- token manager ----

    func testTokenIsCachedUntilNearExpiry() {
        var now: Int64 = 100
        var asked = 0
        let m = TokenManager(deviceId: "device-1234567890abcdef", margin: 60, timeout: 1,
                             request: { _, _, _ in asked += 1; return IssuedToken(token: "t\(asked)", expiresAt: 400) },
                             clock: { now })
        XCTAssertEqual(m.get(nodes(1)), "t1")
        XCTAssertEqual(m.get(nodes(1)), "t1")
        now = 339
        XCTAssertEqual(m.get(nodes(1)), "t1")
        now = 341
        XCTAssertEqual(m.get(nodes(1)), "t2")
    }

    func testTokenRequestTriesTheNextNodeOnFailure() {
        var tried: [String] = []
        let m = TokenManager(deviceId: "device-1234567890abcdef", margin: 60, timeout: 1,
                             request: { node, _, _ in
                                 tried.append(node.host)
                                 if node.host == "10.0.0.1" { throw ShieldError.badResponse }
                                 return IssuedToken(token: "ok", expiresAt: 400)
                             }, clock: { 100 })
        XCTAssertEqual(m.get(nodes(2)), "ok")
        XCTAssertEqual(tried, ["10.0.0.1", "10.0.0.2"])
    }

    func testStaleTokenIsUsedWhileEveryNodeRefusesThenNothing() {
        var now: Int64 = 100
        var down = false
        let m = TokenManager(deviceId: "device-1234567890abcdef", margin: 60, timeout: 1,
                             request: { _, _, _ in
                                 if down { throw ShieldError.badResponse }
                                 return IssuedToken(token: "t", expiresAt: 400)
                             }, clock: { now })
        _ = m.get(nodes(1))
        down = true
        now = 350
        XCTAssertEqual(m.get(nodes(1)), "t")
        now = 401
        XCTAssertNil(m.get(nodes(1)))
    }
}
