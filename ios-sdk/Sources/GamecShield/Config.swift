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
    /// Backup names holding the same list (put them under a different domain, ideally at a different DNS
    /// provider). Tried in order when `name` cannot be read or its list does not verify.
    public let fallbackNames: [String]
    /// DNS-over-HTTPS JSON endpoints. Use IP addresses so no lookup is needed to reach them. Add several:
    /// some are unreachable in some countries.
    public let dohProviders: [String]
    /// DNS-over-TLS servers (port 853, or "host:port"), by IP address. Empty = DoH only.
    public let dotServers: [String]
    /// All resolvers are tried at once, started this far apart (DoT first, then DoH, interleaved); the first
    /// answer whose signature verifies wins. A resolver cannot win with a forged list.
    public let resolverStagger: TimeInterval
    public let timeout: TimeInterval
    /// Re-read the records this often.
    public let refreshInterval: TimeInterval
    /// After a failed lookup wait this long before trying again.
    public let retryInterval: TimeInterval
    /// Ask for a new token when the current one expires within this many seconds.
    public let tokenMargin: TimeInterval
    /// When no node can be reached the list is re-read at once instead of waiting for `refreshInterval`,
    /// but not more often than this.
    public let urgentRefresh: TimeInterval
    /// Keeps the last good list across restarts, e.g. `UserDefaultsListStore()`.
    public let store: ListStore?

    public init(name: String, publicKey: String, deviceId: String,
                fallbackNames: [String] = [],
                dohProviders: [String] = DnsDefaults.doh,
                dotServers: [String] = DnsDefaults.dot,
                resolverStagger: TimeInterval = 0.2,
                timeout: TimeInterval = 5, refreshInterval: TimeInterval = 600,
                retryInterval: TimeInterval = 30, tokenMargin: TimeInterval = 60,
                urgentRefresh: TimeInterval = 3,
                store: ListStore? = nil) throws {
        guard isValidDeviceId(deviceId) else { throw ShieldError.invalidDeviceId }
        guard !(dohProviders.isEmpty && dotServers.isEmpty) else { throw ShieldError.emptyNodeList }
        self.name = name
        self.publicKey = publicKey
        self.deviceId = deviceId
        self.fallbackNames = fallbackNames
        self.dohProviders = dohProviders
        self.dotServers = dotServers
        self.resolverStagger = resolverStagger
        self.timeout = timeout
        self.refreshInterval = refreshInterval
        self.retryInterval = retryInterval
        self.tokenMargin = tokenMargin
        self.urgentRefresh = urgentRefresh
        self.store = store
    }
}

/// Connection state for the game UI. Called on SDK background queues, never on the main thread; hop to the
/// main queue yourself before touching UI. All methods have empty defaults.
public protocol ShieldListener: AnyObject {
    /// An upstream connection through `node` is established.
    func shieldConnected(node: String)
    /// Establishing one failed on every node; the SDK is retrying (attempt 1, 2, ...). The game's socket stays open.
    func shieldRetrying(attempt: Int)
    /// Gave up after `connectRetryWindow`; the game's socket is closed so it can retry itself.
    func shieldConnectFailed()
    /// An established connection was closed because the far side stopped answering.
    func shieldConnectionLost(reason: String)
}

public extension ShieldListener {
    func shieldConnected(node: String) {}
    func shieldRetrying(attempt: Int) {}
    func shieldConnectFailed() {}
    func shieldConnectionLost(reason: String) {}
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
    /// When no node can be reached, keep retrying (backoff with jitter) for this long while the game's socket
    /// stays open, so the game sees a slow connect instead of an immediate failure. 0 = fail at once.
    public let connectRetryWindow: TimeInterval
    public let retryMin: TimeInterval
    public let retryMax: TimeInterval
    /// Close a connection when the game has sent data and nothing at all came back for this long, so the game
    /// notices a dead path in seconds instead of minutes and reconnects. 0 disables. Do not use it for
    /// protocols where the client legitimately sends for a long time without ever getting a reply.
    public let deadAfterUnanswered: TimeInterval
    public let listener: ShieldListener?

    public init(nodes: [Node] = [],
                tokenProvider: (() -> String)? = nil,
                control: ControlConfig? = nil,
                discovery: DiscoveryConfig? = nil,
                localPort: UInt16 = 0,
                connectTimeout: TimeInterval = 1,
                failCooldown: TimeInterval = 30,
                reprobeInterval: TimeInterval = 60,
                connectRetryWindow: TimeInterval = 15,
                retryMin: TimeInterval = 0.2,
                retryMax: TimeInterval = 3,
                deadAfterUnanswered: TimeInterval = 20,
                listener: ShieldListener? = nil) {
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
        self.connectRetryWindow = connectRetryWindow
        self.retryMin = retryMin
        self.retryMax = retryMax
        self.deadAfterUnanswered = deadAfterUnanswered
        self.listener = listener
    }
}
