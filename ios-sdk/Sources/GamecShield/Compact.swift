import CryptoKit
import Foundation

/// The compact list format (edge/shieldlist/compact.go). A record is base64url (no padding) of
/// signature(64, r||s) || content; content is the payload, or nonce(12) || AES-256-GCM(payload) when sealed.
/// The signature is ECDSA P-256 over SHA-256(`domain` || payload). Payload: version(1)=2 kind(1) iat(4)
/// exp(4) count(1) entries; kind 1 = nodes (family(1) address(4|16) port(2) pin(16)), kind 2 = the names to
/// read from next time (length(1) name). Values that do not verify (SPF, other people's records) are skipped.
enum Compact {
    private static let domain = Data("gamec compact list v2\u{0}".utf8)
    private static let sigLen = 64
    private static let headLen = 11
    static let kindList: UInt8 = 1
    static let kindNext: UInt8 = 2
    /// The label in front of a list's name where its next names are published.
    static let nextLabel = "dw2"

    private static let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    static func looksCompact(_ v: String) -> Bool {
        let u = v.utf8
        return (100...4000).contains(u.count) && u.allSatisfy { alphabet.contains($0) }
    }

    static func nextName(_ name: String) -> String {
        nextLabel + "." + (name.hasSuffix(".") ? String(name.dropLast()) : name)
    }

    struct Opened {
        let iat: Int64
        let exp: Int64
        let count: Int
        let entries: [UInt8]
    }

    /// Checks one value; returns its payload if it is of `kind` and signed by `publicKeyB64`, else nil.
    static func open(_ v: String, publicKeyB64: String, listKeyB64: String?, kind: UInt8) -> Opened? {
        guard looksCompact(v), let body = ListVerifier.base64url(v), body.count >= sigLen + headLen,
              let keyDer = Data(base64Encoded: publicKeyB64),
              let key = try? P256.Signing.PublicKey(derRepresentation: keyDer),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: body.prefix(sigLen)) else { return nil }
        let content = Data(body.dropFirst(sigLen))
        // an unsealed record simply fails to decrypt and is checked as it is: the signature decides
        let payload = listKeyB64.flatMap { unseal(content, keyB64: $0) } ?? content
        guard key.isValidSignature(sig, for: domain + payload) else { return nil }
        let p = [UInt8](payload)
        guard p.count >= headLen, p[0] == 2, p[1] == kind else { return nil }
        func u32(_ at: Int) -> Int64 { p[at..<at + 4].reduce(Int64(0)) { $0 << 8 | Int64($1) } }
        return Opened(iat: u32(2), exp: u32(6), count: Int(p[10]), entries: Array(p[headLen...]))
    }

    /// The nodes of a verified list payload, or nil if it is malformed.
    static func nodes(_ o: Opened) -> [Node]? {
        var out: [Node] = []
        var i = 0
        let e = o.entries
        for _ in 0..<o.count {
            guard i < e.count else { return nil }
            let size: Int
            switch e[i] {
            case 4: size = 4
            case 6: size = 16
            default: return nil
            }
            guard i + 1 + size + 2 + 16 <= e.count, let host = address(Array(e[i + 1..<i + 1 + size])) else { return nil }
            let port = UInt16(e[i + 1 + size]) << 8 | UInt16(e[i + 2 + size])
            let pin = Data(e[i + 3 + size..<i + 3 + size + 16]).base64EncodedString()
            out.append(Node(host: host, port: port, pinSha256: pin))
            i += 1 + size + 2 + 16
        }
        return i == e.count && !out.isEmpty ? out : nil
    }

    /// The names of a verified next-names payload, or nil if it is malformed.
    static func names(_ o: Opened) -> [String]? {
        var out: [String] = []
        var i = 0
        let e = o.entries
        for _ in 0..<o.count {
            guard i < e.count else { return nil }
            let len = Int(e[i])
            guard i + 1 + len <= e.count, let s = String(bytes: e[i + 1..<i + 1 + len], encoding: .ascii) else { return nil }
            out.append(s)
            i += 1 + len
        }
        return i == e.count && !out.isEmpty ? out : nil
    }

    /// The usual text form of an IPv4 or IPv6 address.
    private static func address(_ b: [UInt8]) -> String? {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = b.count == 4 ? AF_INET : AF_INET6
        let ok = b.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &buf, socklen_t(buf.count)) } != nil
        return ok ? String(cString: buf) : nil
    }

    private static func unseal(_ data: Data, keyB64: String) -> Data? {
        guard let kd = Data(base64Encoded: keyB64), kd.count == 32,
              let box = try? AES.GCM.SealedBox(combined: data),
              let plain = try? AES.GCM.open(box, using: SymmetricKey(data: kd)) else { return nil }
        return plain
    }
}

/// The signed names to read the list from next time, published at dw2.<name>.
struct NextNames {
    let names: [String]
    let iat: Int64
    let exp: Int64
    let records: [String]
}

enum NextVerifier {
    /// The newest valid next-names record among `records`.
    static func parse(_ records: [String], publicKeyB64: String, now: Int64, listKeyB64: String?) throws -> NextNames {
        var best: NextNames?
        for r in records {
            guard let o = Compact.open(r, publicKeyB64: publicKeyB64, listKeyB64: listKeyB64, kind: Compact.kindNext),
                  let names = Compact.names(o), now <= o.exp else { continue }
            if best == nil || o.iat > best!.iat { best = NextNames(names: names, iat: o.iat, exp: o.exp, records: [r]) }
        }
        guard let b = best else { throw ShieldError.badResponse }
        return b
    }
}
