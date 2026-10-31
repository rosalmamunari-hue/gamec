import CryptoKit
import Foundation
import Network
import Security

/// TLS 1.3 connections that trust exactly one public key (certificate pinning).
enum PinnedTLS {
    // ASN.1 SubjectPublicKeyInfo prefix for an uncompressed P-256 key. SecKey gives only the raw
    // 65-byte point, so we prepend this to get the same bytes Go/Android hash. gencert uses P-256.
    private static let p256SpkiPrefix = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    /// Pin checks are short and never block; a queue of their own keeps them from waiting behind other work.
    private static let verifyQueue = DispatchQueue(label: "gamec.shield.verify")

    static func pin(of cert: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(cert),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        let digest = SHA256.hash(data: p256SpkiPrefix + raw)
        return Data(digest).base64EncodedString()
    }

    /// Whether the key's pin (all 32 bytes) matches the expected one: all of it, or its first 16 bytes as the
    /// compact list carries it. Anything shorter never matches.
    static func matches(_ got: String?, _ want: String) -> Bool {
        guard let g = got.flatMap({ Data(base64Encoded: $0) }), g.count == 32,
              let w = Data(base64Encoded: want), w.count == 16 || w.count == 32 else { return false }
        return g.prefix(w.count) == w
    }

    static func parameters(for node: Node) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_set_verify_block(sec, { _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                  let leaf = chain.first else { return complete(false) }
            complete(matches(pin(of: leaf), node.pinSha256))
        }, verifyQueue)

        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 3
        return NWParameters(tls: tls, tcp: tcp)
    }

    /// Opens a pinned TLS connection; calls back with the ready connection or nil on failure/timeout.
    static func connect(_ node: Node, timeout: TimeInterval, queue: DispatchQueue,
                        completion: @escaping (NWConnection?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(node.host),
                                port: NWEndpoint.Port(rawValue: node.port)!,
                                using: parameters(for: node))
        var finished = false
        let finish: (NWConnection?) -> Void = { result in
            queue.async {
                guard !finished else { return }
                finished = true
                if result == nil { conn.cancel() }
                completion(result)
            }
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready: finish(conn)
            case .failed, .cancelled: finish(nil)
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { finish(nil) }
    }
}
