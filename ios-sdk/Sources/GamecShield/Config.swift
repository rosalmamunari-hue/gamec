import Foundation

public enum ShieldError: Error {
    case invalidDeviceId
    case badSignature
    case emptyNodeList
    case badResponse
}

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

/// Where tokens and the node list come from: the control service (see /control).
/// The SDK checks the signature on every response, so only the signing PUBLIC key is embedded.
public struct ControlConfig {
    /// Full URL, e.g. https://api.example.com/v1/session
    public let url: URL
    /// Base64 X.509 public key, as printed by `control -gen-key`.
    public let publicKey: String
    /// Stable random id for this install; see `DeviceID.getOrCreate()`.
    public let deviceId: String
    public let timeout: TimeInterval
    /// Fetch a new session when the current one expires within this many seconds.
    public let refreshMargin: TimeInterval

    public init(url: URL, publicKey: String, deviceId: String,
                timeout: TimeInterval = 5, refreshMargin: TimeInterval = 60) throws {
        let ok = (16...64).contains(deviceId.count)
            && deviceId.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
        guard ok else { throw ShieldError.invalidDeviceId }
        self.url = url
        self.publicKey = publicKey
        self.deviceId = deviceId
        self.timeout = timeout
        self.refreshMargin = refreshMargin
    }
}

/// Either give a `control` (recommended: tokens and nodes are fetched and kept fresh automatically),
/// or a fixed `nodes` list plus a `tokenProvider` you implement yourself.
public struct ShieldConfig {
    public let nodes: [Node]
    /// Returns a fresh token issued by your own backend. Keep it fast (cache it); it is called per connection.
    /// The HMAC secret must never ship in the app.
    public let tokenProvider: (() -> String)?
    public let control: ControlConfig?
    /// Local port the game connects to. 0 = pick a free port.
    public let localPort: UInt16
    public let connectTimeout: TimeInterval
    public let failCooldown: TimeInterval
    public let reprobeInterval: TimeInterval

    public init(nodes: [Node] = [],
                tokenProvider: (() -> String)? = nil,
                control: ControlConfig? = nil,
                localPort: UInt16 = 0,
                connectTimeout: TimeInterval = 3,
                failCooldown: TimeInterval = 30,
                reprobeInterval: TimeInterval = 60) {
        precondition(control != nil || (!nodes.isEmpty && tokenProvider != nil),
                     "provide either control, or both nodes and tokenProvider")
        self.nodes = nodes
        self.tokenProvider = tokenProvider
        self.control = control
        self.localPort = localPort
        self.connectTimeout = connectTimeout
        self.failCooldown = failCooldown
        self.reprobeInterval = reprobeInterval
    }
}
