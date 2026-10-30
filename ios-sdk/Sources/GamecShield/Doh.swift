import Foundation

/// Minimal DNS-over-HTTPS TXT lookup using the JSON API (Cloudflare, Google and others serve it).
enum Doh {
    static let cloudflare = "https://cloudflare-dns.com/dns-query"

    /// TXT values for `name` from the first provider that answers with at least one.
    static func queryTxt(name: String, providers: [String], timeout: TimeInterval,
                         get: (URL, TimeInterval) throws -> Data = httpGetDnsJson) -> [String] {
        for base in providers {
            guard var comps = URLComponents(string: base) else { continue }
            comps.queryItems = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "type", value: "TXT")]
            guard let url = comps.url else { continue }
            if let values = try? parse(get(url, timeout)), !values.isEmpty { return values }
        }
        return []
    }

    private struct Reply: Decodable {
        let Status: Int?
        let Answer: [Answer]?
        struct Answer: Decodable { let type: Int?; let data: String? }
    }

    static func parse(_ json: Data) throws -> [String] {
        let r = try JSONDecoder().decode(Reply.self, from: json)
        guard r.Status == 0 else { return [] }
        return (r.Answer ?? []).compactMap { a in
            guard a.type == 16, let d = a.data else { return nil } // 16 = TXT
            return joinTxtStrings(d)
        }
    }

    /// A TXT value arrives as `"part1" "part2"` (one quoted string per 255 bytes); join the parts.
    static func joinTxtStrings(_ data: String) -> String {
        let d = data.trimmingCharacters(in: .whitespaces)
        guard d.hasPrefix("\"") else { return d }
        var out = ""
        var inQuote = false
        var escaped = false
        for c in d {
            if inQuote {
                if escaped { out.append(c); escaped = false }
                else if c == "\\" { escaped = true }
                else if c == "\"" { inQuote = false }
                else { out.append(c) }
            } else if c == "\"" {
                inQuote = true
            }
        }
        return out
    }
}

func httpGetDnsJson(_ url: URL, _ timeout: TimeInterval) throws -> Data {
    var req = URLRequest(url: url, timeoutInterval: timeout)
    req.setValue("application/dns-json", forHTTPHeaderField: "accept")
    var result: Result<Data, Error> = .failure(ShieldError.badResponse)
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: req) { data, resp, err in
        if let err = err {
            result = .failure(err)
        } else if let http = resp as? HTTPURLResponse, http.statusCode == 200, let data = data {
            result = .success(data)
        }
        done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + timeout + 2)
    return try result.get()
}
