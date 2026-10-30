import CryptoKit
import Foundation
import XCTest
@testable import GamecShield

/// Pure tests for signature checking and session caching; no network or edge node needed.
final class SessionManagerTests: XCTestCase {
    private func payload(token: String = "tok", expiresAt: Int64 = 1000, pin: String = "pinA") -> Data {
        Data("""
        {"nodes":[{"host":"10.0.0.1","port":30800,"pin":"\(pin)"}],"token":"\(token)","issued_at":0,"expires_at":\(expiresAt)}
        """.utf8)
    }

    private func envelope(_ key: P256.Signing.PrivateKey, _ payload: Data) throws -> Data {
        let sig = try key.signature(for: payload).derRepresentation
        let json = "{\"payload\":\"\(payload.base64EncodedString())\",\"sig\":\"\(sig.base64EncodedString())\"}"
        return Data(json.utf8)
    }

    private func pub(_ key: P256.Signing.PrivateKey) -> String {
        key.publicKey.derRepresentation.base64EncodedString()
    }

    private func config(_ key: P256.Signing.PrivateKey) throws -> ControlConfig {
        try ControlConfig(url: URL(string: "http://unused")!, publicKey: pub(key),
                          deviceId: "device-1234567890abcdef", refreshMargin: 60)
    }

    func testValidEnvelopeParses() throws {
        let k = P256.Signing.PrivateKey()
        let s = try SessionVerifier.parse(try envelope(k, payload()), publicKeyB64: pub(k))
        XCTAssertEqual(s.token, "tok")
        XCTAssertEqual(s.nodes, [Node(host: "10.0.0.1", port: 30800, pinSha256: "pinA")])
        XCTAssertEqual(s.expiresAt, 1000)
    }

    func testTamperedPayloadIsRejected() throws {
        let k = P256.Signing.PrivateKey()
        let good = try JSONSerialization.jsonObject(with: try envelope(k, payload(pin: "pinA"))) as! [String: String]
        let evil = payload(pin: "pinX").base64EncodedString()
        let forged = Data("{\"payload\":\"\(evil)\",\"sig\":\"\(good["sig"]!)\"}".utf8)
        XCTAssertThrowsError(try SessionVerifier.parse(forged, publicKeyB64: pub(k)))
    }

    func testResponseSignedByAnotherKeyIsRejected() throws {
        let attacker = P256.Signing.PrivateKey()
        let real = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try SessionVerifier.parse(try envelope(attacker, payload()), publicKeyB64: pub(real)))
    }

    func testSessionIsCachedUntilNearExpiry() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 100
        var fetches = 0
        let env = try envelope(k, payload(expiresAt: 400))
        let m = SessionManager(cfg: try config(k), fetch: { _ in fetches += 1; return env }, clock: { now })
        let first = m.get()
        XCTAssertNotNil(first)
        XCTAssertTrue(first === m.get())
        XCTAssertEqual(fetches, 1)

        now = 339 // 61s left: still outside the 60s refresh margin
        XCTAssertTrue(first === m.get())
        XCTAssertEqual(fetches, 1)

        now = 341 // 59s left: refresh
        _ = m.get()
        XCTAssertEqual(fetches, 2)
    }

    func testStaleSessionIsUsedWhileControlIsDown() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 100
        var down = false
        let env = try envelope(k, payload(expiresAt: 400))
        let m = SessionManager(cfg: try config(k),
                               fetch: { _ in if down { throw ShieldError.badResponse }; return env },
                               clock: { now })
        let first = m.get()
        down = true
        now = 350 // inside the refresh margin but the token is still valid
        XCTAssertTrue(first === m.get())
    }

    func testNoSessionOnceExpiredAndControlIsDown() throws {
        let k = P256.Signing.PrivateKey()
        var now: Int64 = 100
        var down = false
        let env = try envelope(k, payload(expiresAt: 400))
        let m = SessionManager(cfg: try config(k),
                               fetch: { _ in if down { throw ShieldError.badResponse }; return env },
                               clock: { now })
        _ = m.get()
        down = true
        now = 401
        XCTAssertNil(m.get())
    }

    func testBadSignatureNeverBecomesTheCurrentSession() throws {
        let k = P256.Signing.PrivateKey()
        let forged = try envelope(P256.Signing.PrivateKey(), payload())
        let m = SessionManager(cfg: try config(k), fetch: { _ in forged }, clock: { 100 })
        XCTAssertNil(m.get())
    }

    func testDeviceIdIsValidated() {
        XCTAssertThrowsError(try ControlConfig(url: URL(string: "http://x")!, publicKey: "k",
                                               deviceId: "has.dots.and.is.long.enough.123"))
    }
}
