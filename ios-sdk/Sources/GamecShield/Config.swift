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

func isValidDeviceId(_ id: String) -> Bool {
    (16...64).contains(id.count)
        && id.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
}

/// Finds the nodes through DNS: a signed list published as TXT records, fetched with DNS-over-HTTPS.
/// Tokens come from the nodes themselves, so no separate server is needed. Make the list with
/// `signlist` (see /edge/cmd/signlist) on your own computer; only its PUBLIC key goes in the app.
public struct DiscoveryConfig {
    /// DNS name holding the TXT records, e.g. "_gs.example.com".
    public let name: String
    /// Base64 X.509 public key printed by `signlist -gen-key`.
    public let publicKey: String
    /// Stable random id for this install; see `DeviceID.getOrCreate()`.
    public let deviceId: String
    /// DoH JSON endpoints, tried in order. Add more than one: some are unreachable in some countries.
    public let dohProviders: [String]
    public let timeout: TimeInterval
    /// Re-read the records this often.
    public let refreshInterval: TimeInterval
    /// After a failed lookup wait this long before trying again.
    public let retryInterval: TimeInterval
    /// Ask for a new token when the current one expires within this many seconds.
    public let tokenMargin: TimeInterval
    /// Keeps the last good list across restarts, e.g. `UserDefaultsListStore()`.
    public let store: ListStore?

    public init(name: String, publicKey: String, deviceId: String,
                dohProviders: [String] = [Doh.cloudflare],
                timeout: TimeInterval = 5, refreshInterval: TimeInterval = 600,
                retryInterval: TimeInterval = 30, tokenMargin: TimeInterval = 60,
                store: ListStore? = nil) throws {
        guard isValidDeviceId(deviceId), !dohProviders.isEmpty else { throw ShieldError.invalidDeviceId }
        self.name = name
        self.publicKey = publicKey
        self.deviceId = deviceId
        self.dohProviders = dohProviders
        self.timeout = timeout
        self.refreshInterval = refreshInterval
        self.retryInterval = retryInterval
        self.tokenMargin = tokenMargin
        self.store = store
    }
}

/// Pick one way to learn nodes and tokens:
///  - `discovery`: nodes from signed DNS TXT records, tokens from the nodes (no server of your own);
///  - `control`: nodes and tokens from your control service;
///  - `nodes` + `tokenProvider`: a fixed list and tokens from your own backend.
public struct ShieldConfig {
    public let nodes: [Node]
    /// Returns a fresh token issued by your own backend. Keep it fast (cache it); it is called per connection.
    /// The HMAC secret must never ship in the app.
    public let tokenProvider: (() -> String)?
    public let control: ControlConfig?
    public let discovery: DiscoveryConfig?
    /// Local port the game connects to. 0 = pick a free port.
    public let localPort: UInt16
    public let connectTimeout: TimeInterval
    public let failCooldown: TimeInterval
    public let reprobeInterval: TimeInterval

    public init(nodes: [Node] = [],
                tokenProvider: (() -> String)? = nil,
                control: ControlConfig? = nil,
                discovery: DiscoveryConfig? = nil,
                localPort: UInt16 = 0,
                connectTimeout: TimeInterval = 3,
                failCooldown: TimeInterval = 30,
                reprobeInterval: TimeInterval = 60) {
        precondition(discovery != nil || control != nil || (!nodes.isEmpty && tokenProvider != nil),
                     "provide discovery, control, or both nodes and tokenProvider")
        self.nodes = nodes
        self.tokenProvider = tokenProvider
        self.control = control
        self.discovery = discovery
        self.localPort = localPort
        self.connectTimeout = connectTimeout
        self.failCooldown = failCooldown
        self.reprobeInterval = reprobeInterval
    }
}
