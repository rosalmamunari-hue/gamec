import CryptoKit
import Foundation
import Network
import XCTest
@testable import GamecShield

/// End-to-end tests against a locally started edge node (see codemagic.yaml).
/// They are skipped unless GAMEC_TEST_PIN is set.
final class ShieldTests: XCTestCase {
    private let host = "127.0.0.1"
    private let port: UInt16 = 30800
    private var pin: String { ProcessInfo.processInfo.environment["GAMEC_TEST_PIN"] ?? "" }
    private var secret: String { ProcessInfo.processInfo.environment["GAMEC_TEST_SECRET"] ?? "" }

    override func setUpWithError() throws {
        try XCTSkipIf(pin.isEmpty, "GAMEC_TEST_PIN not set")
    }

    /// Same format the edge checks: "<uid>.<unix ts>.<hex hmac-sha256(secret, uid.ts)>"
    private func makeToken(secret: String) -> String {
        let body = "ios." + String(Int(Date().timeIntervalSince1970))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(body.utf8),
                                                  using: SymmetricKey(data: Data(secret.utf8)))
        return body + "." + mac.map { String(format: "%02x", $0) }.joined()
    }

    private func tlsConnects(pin: String) -> Bool {
        let node = Node(host: host, port: port, pinSha256: pin)
        let q = DispatchQueue(label: "test.tls")
        let exp = expectation(description: "connect")
        var ok = false
        PinnedTLS.connect(node, timeout: 5, queue: q) { conn in
            ok = conn != nil
            conn?.cancel()
            exp.fulfill()
        }
        wait(for: [exp], timeout: 8)
        return ok
    }

    /// Sends `text` to the local proxy and returns what comes back (nil if the connection was closed).
    private func echo(viaProxyPort proxyPort: UInt16, text: String) -> String? {
        let conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: proxyPort)!, using: .tcp)
        let done = DispatchSemaphore(value: 0)
        var result: String?
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: Data(text.utf8), completion: .contentProcessed { _ in })
                conn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, _ in
                    if let d = data, !d.isEmpty { result = String(data: d, encoding: .utf8) }
                    done.signal()
                }
            case .failed, .cancelled:
                done.signal()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "test.client"))
        _ = done.wait(timeout: .now() + 6)
        conn.cancel()
        return result
    }

    func testCorrectPinIsAccepted() {
        XCTAssertTrue(tlsConnects(pin: pin), "pin computed by Go (gencert) must match the one computed on iOS")
    }

    func testWrongPinIsRefused() {
        XCTAssertFalse(tlsConnects(pin: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
    }

    func testValidTokenRelaysToOrigin() throws {
        try XCTSkipIf(secret.isEmpty, "GAMEC_TEST_SECRET not set")
        let cfg = ShieldConfig(nodes: [Node(host: host, port: port, pinSha256: pin)],
                               tokenProvider: { [self] in makeToken(secret: secret) })
        let shield = ShieldClient(config: cfg)
        let proxyPort = try shield.start()
        defer { shield.stop() }
        XCTAssertEqual(echo(viaProxyPort: proxyPort, text: "ping"), "ping")
    }

    func testBadTokenIsNotRelayed() throws {
        let cfg = ShieldConfig(nodes: [Node(host: host, port: port, pinSha256: pin)],
                               tokenProvider: { [self] in makeToken(secret: "wrong-secret") })
        let shield = ShieldClient(config: cfg)
        let proxyPort = try shield.start()
        defer { shield.stop() }
        XCTAssertNil(echo(viaProxyPort: proxyPort, text: "ping"))
    }

    func testControlModeFetchesTokenAndNodesAutomatically() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["GAMEC_TEST_CONTROL_URL"] == nil || env["GAMEC_TEST_CONTROL_PUBKEY"] == nil,
                      "control env not set")
        let control = try ControlConfig(url: URL(string: env["GAMEC_TEST_CONTROL_URL"]!)!,
                                        publicKey: env["GAMEC_TEST_CONTROL_PUBKEY"]!,
                                        deviceId: "device-ios-e2e-000000001")
        let shield = ShieldClient(config: ShieldConfig(control: control))
        let proxyPort = try shield.start()
        defer { shield.stop() }
        XCTAssertEqual(echo(viaProxyPort: proxyPort, text: "ping"), "ping")
    }

    func testControlModeRefusesAServiceSignedByTheWrongKey() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["GAMEC_TEST_CONTROL_URL"] == nil, "control env not set")
        let wrong = P256.Signing.PrivateKey().publicKey.derRepresentation.base64EncodedString()
        let control = try ControlConfig(url: URL(string: env["GAMEC_TEST_CONTROL_URL"]!)!,
                                        publicKey: wrong, deviceId: "device-ios-e2e-000000002")
        let shield = ShieldClient(config: ShieldConfig(control: control))
        let proxyPort = try shield.start()
        defer { shield.stop() }
        XCTAssertNil(echo(viaProxyPort: proxyPort, text: "ping"))
    }

    func testFailoverSkipsDeadNode() throws {
        try XCTSkipIf(secret.isEmpty, "GAMEC_TEST_SECRET not set")
        let dead = Node(host: host, port: 1, pinSha256: pin)
        let good = Node(host: host, port: port, pinSha256: pin)
        let cfg = ShieldConfig(nodes: [dead, good],
                               tokenProvider: { [self] in makeToken(secret: secret) })
        let shield = ShieldClient(config: cfg)
        let proxyPort = try shield.start()
        defer { shield.stop() }
        XCTAssertEqual(echo(viaProxyPort: proxyPort, text: "ping"), "ping")
    }
}
