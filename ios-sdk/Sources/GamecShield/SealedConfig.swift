import CryptoKit
import Foundation

/// The names and keys of a `DiscoveryConfig` packed into one opaque string (made with
/// `signlist -seal-config <passphrase> -name ... -pub ...`), so they are not in the app package as plain text.
/// The passphrase ships in the app too: this stops casual scraping (grep, "strings"), not someone who reverses it.
///
///     let o = try SealedConfig.open(blob, passphrase: pass)
///     let d = try DiscoveryConfig(name: o.name, publicKey: o.publicKey, deviceId: id, listKey: o.listKey,
///                                 fallbackNames: o.fallbackNames, store: UserDefaultsListStore())
public struct SealedConfig {
    public let name: String
    public let fallbackNames: [String]
    public let publicKey: String
    public let listKey: String?

    private struct Raw: Decodable {
        let n: String
        let f: [String]?
        let k: String
        let l: String?
    }

    /// Throws if the passphrase is wrong or the string is damaged.
    public static func open(_ blob: String, passphrase: String) throws -> SealedConfig {
        guard let raw = ListVerifier.base64url(blob) else { throw ShieldError.badResponse }
        var material = Data("gamec-config\0".utf8)
        material.append(Data(passphrase.utf8))
        let key = SymmetricKey(data: SHA256.hash(data: material))
        guard let box = try? AES.GCM.SealedBox(combined: raw),
              let plain = try? AES.GCM.open(box, using: key),
              let r = try? JSONDecoder().decode(Raw.self, from: plain) else { throw ShieldError.badResponse }
        return SealedConfig(name: r.n, fallbackNames: r.f ?? [], publicKey: r.k,
                            listKey: (r.l?.isEmpty ?? true) ? nil : r.l)
    }
}
