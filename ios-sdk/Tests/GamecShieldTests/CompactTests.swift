import CryptoKit
import Foundation
import XCTest
@testable import GamecShield

/// The compact list format and the dw2. next names, against records made by the Go code.
final class CompactTests: XCTestCase {
    // made by edge/shieldlist TestPrintCompactVectors; the nodes are 47.243.177.67:48860, 47.76.67.157:30522, [2001:db8::7]:23198
    private let goPub = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElsAZxR7AEl64NX4RaXbpaBab5U3jDxLp8WQIMjneko3g/uUmc9WWOu34ph8Aqd67GUh+tBHqVnsPn7acraHmpQ=="
    private let goSeal = "QiPWaFZWbmnziDuBA/lFxT3TsJmVZ6ySs5JLHZC22rE="
    private let goList = "05jl-6J5tBh3F9Dj2YcmpWgGecRoAHaIHtP0NzB1CBrWvfQoU_sKf-lwzg9bVf00rbPuOJtitZxAzW3eN6lGjAIBa0nSAMlF4QADBC_zsUO-3A5Imh61-v-EYCGlSzmyQSwEL0xDnXc6O16v-J3Ysb-CLyxboxN8TAYgAQ24AAAAAAAAAAAAAAAHWp5zrlK0J7Bu6Xak9NAW7Zm7"
    private let goSealed = "cppiHaCUbQIr3pONhbs6gxjYgoEHb8IUsscXJYySWGApk5cizF_nAOxZ4TmWRcwyzDI9LT63uutSQ3OiuzvF54uuEmV579lUPujR13U8ECTW1EjNyvIEAEvD2fy3Cf-xXiQfIDvyEg-5YyFCjrGMmG6p9v710wB0MFrE1TrRFVqUyHJBL4OIc5iWVY0W4jiQ8vPmaw99J8ArFtbLsOk61dV97M1l5gUFk-iruBEAeCQXZvq7R8oVgw"
    private let goNext = "JagTUudID-Esiz13lPFrgLCuBFJxn9PipQUPIloLqGoidDwUj2pJi6MS_m7xb167jlUG6-cos9XfuXmw_05_HgICa0nSAMlF4QACDWEuZXhhbXBsZS5jb20NYi5leGFtcGxlLm5ldA"
    private let goNodes = [
        Node(host: "47.243.177.67", port: 48860, pinSha256: "DkiaHrX6/4RgIaVLObJBLA=="),
        Node(host: "47.76.67.157", port: 30522, pinSha256: "O16v+J3Ysb+CLyxboxN8TA=="),
        Node(host: "2001:db8::7", port: 23198, pinSha256: "c65StCewbul2pPTQFu2Zuw=="),
    ]

    func testACompactListMadeByTheGoCodeIsReadHere() throws {
        let l = try ListVerifier.parse(["v=spf1 -all", goList], publicKeyB64: goPub, now: 1_800_000_100)
        XCTAssertEqual(l.nodes, goNodes)
        XCTAssertEqual(l.iat, 1_800_000_000)
        XCTAssertEqual(l.records, [goList])
    }

    func testASealedCompactListNeedsTheKey() throws {
        XCTAssertEqual(try ListVerifier.parse([goSealed], publicKeyB64: goPub, now: 1_800_000_100, listKeyB64: goSeal).nodes, goNodes)
        XCTAssertThrowsError(try ListVerifier.parse([goSealed], publicKeyB64: goPub, now: 1_800_000_100))
        XCTAssertEqual(try ListVerifier.parse([goList], publicKeyB64: goPub, now: 1_800_000_100, listKeyB64: goSeal).nodes, goNodes,
                       "an app with a key still reads a plain list")
    }

    func testNextNamesMadeByTheGoCodeAreReadHere() throws {
        let n = try NextVerifier.parse(["other", goNext], publicKeyB64: goPub, now: 1_800_000_100, listKeyB64: nil)
        XCTAssertEqual(n.names, ["a.example.com", "b.example.net"])
        XCTAssertThrowsError(try ListVerifier.parse([goNext], publicKeyB64: goPub, now: 1_800_000_100)) // no node list
        XCTAssertThrowsError(try NextVerifier.parse([goList], publicKeyB64: goPub, now: 1_800_000_100, listKeyB64: nil))
    }

    func testAChangedOrForeignOrExpiredCompactListIsRejected() throws {
        var b = ListVerifier.base64url(goList)!
        b[b.count - 1] ^= 1
        XCTAssertThrowsError(try ListVerifier.parse([b64url(b)], publicKeyB64: goPub, now: 1_800_000_100))
        XCTAssertThrowsError(try ListVerifier.parse([goList], publicKeyB64: pub(P256.Signing.PrivateKey()), now: 1_800_000_100))
        XCTAssertThrowsError(try ListVerifier.parse([goList], publicKeyB64: goPub, now: 5_000_000_000))
    }

    func testTheDirectoryReadsTheNextNamesFromDw2AndUsesThemFirst() throws {
        let k = P256.Signing.PrivateKey()
        let answers = [
            "_gs.example.com": [try compactList(k, iat: 100)],
            "dw2._gs.example.com": [try compactNext(k, iat: 100, ["alt.example.net", "_gs.example.com"])],
        ]
        let store = MemoryStore()
        let c = try DiscoveryConfig(name: "_gs.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef", store: store)
        let d = NodeDirectory(cfg: c, queryTxt: { answers[$0] ?? [] }, clock: { 200 })
        XCTAssertEqual(d.get()?.nodes.count, 2)
        let deadline = Date().addingTimeInterval(5)
        while d.namesForTest().first != "alt.example.net" && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertEqual(d.namesForTest(), ["alt.example.net", "_gs.example.com"])
        while store.load().count < 2 && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        // a restart remembers both: the list and where to look next
        let again = NodeDirectory(cfg: try DiscoveryConfig(name: "_gs.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef",
                                                           store: store), queryTxt: { _ in [] }, clock: { 200 })
        XCTAssertEqual(again.namesForTest().first, "alt.example.net")
    }

    func testAForgedDw2RecordIsIgnored() throws {
        let k = P256.Signing.PrivateKey()
        let answers = [
            "_gs.example.com": [try compactList(k, iat: 100)],
            "dw2._gs.example.com": [try compactNext(P256.Signing.PrivateKey(), iat: 100, ["evil.example.net"])],
        ]
        let c = try DiscoveryConfig(name: "_gs.example.com", publicKey: pub(k), deviceId: "device-1234567890abcdef")
        let d = NodeDirectory(cfg: c, queryTxt: { answers[$0] ?? [] }, clock: { 200 })
        _ = d.get()
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(d.namesForTest(), ["_gs.example.com"])
    }

    func testASixteenBytePinMatchesAndShorterOnesNever() {
        let full = Data((0..<32).map { UInt8($0) })
        let got = full.base64EncodedString()
        XCTAssertTrue(PinnedTLS.matches(got, got))
        XCTAssertTrue(PinnedTLS.matches(got, full.prefix(16).base64EncodedString()))
        var wrong = Data(full.prefix(16))
        wrong[15] ^= 1
        XCTAssertFalse(PinnedTLS.matches(got, wrong.base64EncodedString()))
        XCTAssertFalse(PinnedTLS.matches(got, full.prefix(8).base64EncodedString()), "a short prefix must never count")
        XCTAssertFalse(PinnedTLS.matches(nil, got))
    }

    // ---- helpers ----

    private final class MemoryStore: ListStore {
        private let lock = NSLock()
        private var recs: [String] = []
        func load() -> [String] { lock.lock(); defer { lock.unlock() }; return recs }
        func save(_ records: [String]) { lock.lock(); recs = records; lock.unlock() }
    }

    private func pub(_ k: P256.Signing.PrivateKey) -> String { k.publicKey.derRepresentation.base64EncodedString() }

    private func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func header(_ kind: UInt8, iat: UInt32, count: Int) -> Data {
        var d = Data([2, kind])
        for v in [iat, 10_000] { d += [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
        d.append(UInt8(count))
        return d
    }

    /// Signs a compact payload the way the Go code does (r||s over SHA-256(domain || payload)).
    private func sign(_ k: P256.Signing.PrivateKey, _ payload: Data) throws -> String {
        let sig = try k.signature(for: Data("gamec compact list v2\u{0}".utf8) + payload).rawRepresentation
        return b64url(sig + payload)
    }

    private func compactList(_ k: P256.Signing.PrivateKey, iat: UInt32) throws -> String {
        var p = header(1, iat: iat, count: 2)
        for last: UInt8 in [1, 2] { p += [4, 10, 0, 0, last, 0x78, 0x50] + [UInt8](repeating: 7, count: 16) }
        return try sign(k, p)
    }

    private func compactNext(_ k: P256.Signing.PrivateKey, iat: UInt32, _ names: [String]) throws -> String {
        var p = header(2, iat: iat, count: names.count)
        for n in names { p.append(UInt8(n.utf8.count)); p += Data(n.utf8) }
        return try sign(k, p)
    }
}
