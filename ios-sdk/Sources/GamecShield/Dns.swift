import Foundation
import Network

enum DnsError: Error {
    case malformed(String)
}

/// The few bytes of DNS wire format needed to ask for TXT records and read the answer (RFC 1035).
enum DnsWire {
    private static let typeTXT: UInt16 = 16
    private static let classIN: UInt16 = 1

    static func buildQuery(name: String, id: UInt16) throws -> Data {
        var out = Data()
        func u16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF)) }
        u16(id)
        u16(0x0100) // standard query, recursion desired
        u16(1); u16(0); u16(0); u16(0)
        for label in name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".", omittingEmptySubsequences: false) {
            let b = Array(label.utf8)
            guard !b.isEmpty, b.count <= 63, label.allSatisfy({ $0.isASCII }) else { throw DnsError.malformed("bad DNS label in \(name)") }
            out.append(UInt8(b.count))
            out.append(contentsOf: b)
        }
        out.append(0)
        u16(typeTXT)
        u16(classIN)
        return out
    }

    /// TXT values in the answer (strings of one record joined). Empty for "no such name"; throws if malformed.
    static func parseTxt(_ data: Data, expectId: UInt16) throws -> [String] {
        let msg = [UInt8](data)
        guard msg.count >= 12 else { throw DnsError.malformed("short DNS message") }
        func u16(_ p: Int) throws -> Int {
            guard p + 2 <= msg.count else { throw DnsError.malformed("read past the message") }
            return Int(msg[p]) << 8 | Int(msg[p + 1])
        }
        guard try u16(0) == Int(expectId) else { throw DnsError.malformed("DNS id mismatch") }
        let flags = try u16(2)
        guard flags & 0x8000 != 0 else { throw DnsError.malformed("not a response") }
        switch flags & 0xF {
        case 0: break
        case 3: return [] // NXDOMAIN
        default: throw DnsError.malformed("DNS error code \(flags & 0xF)")
        }
        let qd = try u16(4)
        let an = try u16(6)

        func skipName(_ start: Int) throws -> Int {
            var p = start
            while true {
                guard p < msg.count else { throw DnsError.malformed("name runs past the message") }
                let len = Int(msg[p])
                if len == 0 { return p + 1 }
                if len & 0xC0 == 0xC0 { return p + 2 } // compression pointer ends the name
                p += 1 + len
            }
        }

        var pos = 12
        for _ in 0..<qd { pos = try skipName(pos) + 4 }
        var out: [String] = []
        for _ in 0..<an {
            pos = try skipName(pos)
            guard pos + 10 <= msg.count else { throw DnsError.malformed("truncated answer") }
            let type = try u16(pos)
            let rdLen = try u16(pos + 8)
            pos += 10
            guard pos + rdLen <= msg.count else { throw DnsError.malformed("truncated rdata") }
            if type == Int(typeTXT) {
                var joined = ""
                var p = pos
                let end = pos + rdLen
                while p < end {
                    let n = Int(msg[p])
                    guard p + 1 + n <= end else { throw DnsError.malformed("bad TXT string") }
                    joined += String(decoding: msg[(p + 1)..<(p + 1 + n)], as: UTF8.self)
                    p += 1 + n
                }
                out.append(joined)
            }
            pos += rdLen
        }
        return out
    }
}

/// DNS over TLS (RFC 7858): the same wire messages, framed with a 2-byte length, over TLS on port 853.
enum Dot {
    /// Opens a connection (started on `queue`) and calls back with it, or nil on failure. Must always call back.
    typealias Connect = (_ host: String, _ port: UInt16, _ timeout: TimeInterval, _ queue: DispatchQueue,
                         _ done: @escaping (NWConnection?) -> Void) -> Void

    /// TLS with the system trust store; the certificate must match `host` (an IP address works if it is in the SAN).
    static let tlsConnect: Connect = { host, port, timeout, queue, done in
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = Int(timeout.rounded(.up))
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                using: NWParameters(tls: NWProtocolTLS.Options(), tcp: tcp))
        var finished = false
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready: if !finished { finished = true; done(conn) }
            case .failed, .cancelled: if !finished { finished = true; done(nil) }
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            if !finished {
                finished = true
                conn.cancel()
                done(nil)
            }
        }
    }

    /// Blocking; call it off the main thread.
    static func query(host: String, port: UInt16 = 853, name: String, timeout: TimeInterval,
                      connect: Connect = tlsConnect) throws -> [String] {
        let id = UInt16.random(in: 0...UInt16.max)
        let q = try DnsWire.buildQuery(name: name, id: id)
        let queue = DispatchQueue(label: "gamec.dot")

        let ready = DispatchSemaphore(value: 0)
        var connection: NWConnection?
        connect(host, port, timeout, queue) { c in connection = c; ready.signal() }
        ready.wait()
        guard let conn = connection else { throw DnsError.malformed("could not connect to \(host):\(port)") }
        defer { conn.cancel() }

        let frame = Data([UInt8(q.count >> 8), UInt8(q.count & 0xFF)]) + q
        let sent = DispatchSemaphore(value: 0)
        var sendError: NWError?
        conn.send(content: frame, completion: .contentProcessed { e in sendError = e; sent.signal() })
        guard sent.wait(timeout: .now() + timeout) == .success, sendError == nil else {
            throw DnsError.malformed("could not send the query")
        }
        let header = try TokenClient.receiveExactly(conn, 2, timeout)
        let len = Int(header[0]) << 8 | Int(header[1])
        guard len >= 12 else { throw DnsError.malformed("bad response length \(len)") }
        let body = try TokenClient.receiveExactly(conn, len, timeout)
        return try DnsWire.parseTxt(body, expectId: id)
    }
}

/// Plain DNS (RFC 1035): UDP on port 53, falling back to TCP when the UDP reply is truncated (TC bit).
enum Do53 {
    private static func truncated(_ msg: Data) -> Bool {
        guard msg.count >= 4 else { return false }
        let flags = Int(msg[2]) << 8 | Int(msg[3])
        return flags & 0x0200 != 0
    }

    /// Blocking; call it off the main thread.
    static func query(host: String, port: UInt16 = 53, name: String, timeout: TimeInterval) throws -> [String] {
        let id = UInt16.random(in: 0...UInt16.max)
        let q = try DnsWire.buildQuery(name: name, id: id)
        let queue = DispatchQueue(label: "gamec.do53")

        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .udp)
        let ready = DispatchSemaphore(value: 0)
        var ok = false
        conn.stateUpdateHandler = { state in
            if case .ready = state { if !ok { ok = true; ready.signal() } }
            if case .failed = state { if !ok { ready.signal() } }
        }
        conn.start(queue: queue)
        defer { conn.cancel() }
        guard ready.wait(timeout: .now() + timeout) == .success, ok else {
            throw DnsError.malformed("could not reach \(host):\(port)")
        }

        let sent = DispatchSemaphore(value: 0)
        var sendError: NWError?
        conn.send(content: q, completion: .contentProcessed { e in sendError = e; sent.signal() })
        guard sent.wait(timeout: .now() + timeout) == .success, sendError == nil else {
            throw DnsError.malformed("could not send the query")
        }

        let got = DispatchSemaphore(value: 0)
        var reply: Data?
        conn.receiveMessage { data, _, _, error in reply = (error == nil) ? data : nil; got.signal() }
        guard got.wait(timeout: .now() + timeout) == .success, let msg = reply else {
            throw DnsError.malformed("no reply from \(host):\(port)")
        }
        if !truncated(msg) { return try DnsWire.parseTxt(msg, expectId: id) }
        return try queryTcp(host: host, port: port, query: q, id: id, timeout: timeout, queue: queue)
    }

    private static func queryTcp(host: String, port: UInt16, query: Data, id: UInt16, timeout: TimeInterval,
                                 queue: DispatchQueue) throws -> [String] {
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = Int(timeout.rounded(.up))
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                using: NWParameters(tls: nil, tcp: tcp))
        let ready = DispatchSemaphore(value: 0)
        var ok = false
        conn.stateUpdateHandler = { state in
            if case .ready = state { if !ok { ok = true; ready.signal() } }
            if case .failed = state { if !ok { ready.signal() } }
        }
        conn.start(queue: queue)
        defer { conn.cancel() }
        guard ready.wait(timeout: .now() + timeout) == .success, ok else {
            throw DnsError.malformed("could not reach \(host):\(port) over TCP")
        }
        let frame = Data([UInt8(query.count >> 8), UInt8(query.count & 0xFF)]) + query
        let sent = DispatchSemaphore(value: 0)
        var sendError: NWError?
        conn.send(content: frame, completion: .contentProcessed { e in sendError = e; sent.signal() })
        guard sent.wait(timeout: .now() + timeout) == .success, sendError == nil else {
            throw DnsError.malformed("could not send the query over TCP")
        }
        let header = try TokenClient.receiveExactly(conn, 2, timeout)
        let len = Int(header[0]) << 8 | Int(header[1])
        guard len >= 12 else { throw DnsError.malformed("bad response length \(len)") }
        let body = try TokenClient.receiveExactly(conn, len, timeout)
        return try DnsWire.parseTxt(body, expectId: id)
    }
}
