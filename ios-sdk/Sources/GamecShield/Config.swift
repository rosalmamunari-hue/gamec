import Foundation

/// An edge node. `pinSha256` is base64(SHA-256(SubjectPublicKeyInfo)) as printed by `gencert`.
public struct Node: Hashable {
    public let host: String
    public let port: UInt16
    public let pinSha256: String

    public init(host: String, port: UInt16, pinSha256: String) {
        self.host = host
        self.port = port
        self.pinSha256 = pinSha256
    }
}

public struct ShieldConfig {
    public let nodes: [Node]
    /// Returns a fresh token issued by your login server. Keep it fast (cache it); it is called per connection.
    /// The HMAC secret must never ship in the app.
    public let tokenProvider: () -> String
    /// Local port the game connects to. 0 = pick a free port.
    public let localPort: UInt16
    public let connectTimeout: TimeInterval
    public let failCooldown: TimeInterval
    public let reprobeInterval: TimeInterval

    public init(nodes: [Node],
                tokenProvider: @escaping () -> String,
                localPort: UInt16 = 0,
                connectTimeout: TimeInterval = 3,
                failCooldown: TimeInterval = 30,
                reprobeInterval: TimeInterval = 60) {
        self.nodes = nodes
        self.tokenProvider = tokenProvider
        self.localPort = localPort
        self.connectTimeout = connectTimeout
        self.failCooldown = failCooldown
        self.reprobeInterval = reprobeInterval
    }
}
