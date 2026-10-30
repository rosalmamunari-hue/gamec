package com.gamec.shield

/** An edge node. [pinSha256] is base64(SHA-256(SubjectPublicKeyInfo)) of the node's certificate. */
data class Node(val host: String, val port: Int, val pinSha256: String) {
    override fun toString() = "$host:$port"
}

/**
 * Where tokens and the node list come from: the control service (see /control).
 * The SDK checks the signature on every response, so only the signing PUBLIC key is embedded.
 */
class ControlConfig(
    /** Full URL, e.g. https://api.example.com/v1/session */
    val url: String,
    /** Base64 X.509 public key, as printed by `control -gen-key`. */
    val publicKey: String,
    /** Stable random id for this install; see [DeviceId.getOrCreate]. */
    val deviceId: String,
    val timeoutMs: Int = 5000,
    /** Fetch a new session when the current one expires within this many seconds. */
    val refreshMarginSec: Long = 60,
) {
    init {
        require(DEVICE_ID.matches(deviceId)) { "deviceId must be 16-64 chars of A-Z a-z 0-9 _ -" }
    }

    private companion object {
        val DEVICE_ID = Regex("^[A-Za-z0-9_-]{16,64}$")
    }
}

/**
 * Finds the nodes through DNS: a signed list published as TXT records, fetched with DNS-over-HTTPS.
 * Tokens come from the nodes themselves, so no separate server is needed. Make the list with
 * `signlist` (see /edge/cmd/signlist) on your own computer; only its PUBLIC key goes in the app.
 */
class DiscoveryConfig(
    /** DNS name holding the TXT records, e.g. "_gs.example.com". */
    val name: String,
    /** Base64 X.509 public key printed by `signlist -gen-key`. */
    val publicKey: String,
    /** Stable random id for this install; see [DeviceId.getOrCreate]. */
    val deviceId: String,
    /** DoH JSON endpoints, tried in order. Add more than one: some are unreachable in some countries. */
    val dohProviders: List<String> = listOf(Doh.CLOUDFLARE),
    val timeoutMs: Int = 5000,
    /** Re-read the records this often. */
    val refreshSec: Long = 600,
    /** After a failed lookup wait this long before trying again. */
    val retrySec: Long = 30,
    /** Ask for a new token when the current one expires within this many seconds. */
    val tokenMarginSec: Long = 60,
    /** Keeps the last good list across restarts, e.g. `PrefsListStore(context)`. */
    val store: ListStore? = null,
) {
    init {
        require(DEVICE_ID.matches(deviceId)) { "deviceId must be 16-64 chars of A-Z a-z 0-9 _ -" }
        require(dohProviders.isNotEmpty()) { "at least one DoH provider is required" }
    }

    private companion object {
        val DEVICE_ID = Regex("^[A-Za-z0-9_-]{16,64}$")
    }
}

/**
 * Connection state for the game UI. Called on SDK worker threads, never on the main thread; post to the
 * UI thread yourself if you touch views. Exceptions thrown here are swallowed.
 */
interface ShieldListener {
    /** An upstream connection through [node] is established. */
    fun onConnected(node: String) {}

    /** Establishing one failed on every node; the SDK is retrying (attempt 1, 2, ...). The game's socket stays open. */
    fun onRetrying(attempt: Int) {}

    /** Gave up after [ShieldConfig.connectRetryWindowMs]; the game's socket is closed so it can retry itself. */
    fun onConnectFailed() {}

    /** An established connection was closed because the far side stopped answering. */
    fun onConnectionLost(reason: String) {}
}

/**
 * Pick one way to learn nodes and tokens:
 *  - [discovery]: nodes from signed DNS TXT records, tokens from the nodes (no server of your own);
 *  - [control]: nodes and tokens from your control service;
 *  - [nodes] + [tokenProvider]: a fixed list and tokens from your own backend.
 */
class ShieldConfig(
    val nodes: List<Node> = emptyList(),
    /** Returns a fresh token issued by your own backend (the HMAC secret must never ship in the app). */
    val tokenProvider: (() -> String)? = null,
    val control: ControlConfig? = null,
    val discovery: DiscoveryConfig? = null,
    /** Local port the game connects to instead of the real server. 0 = pick a free port. */
    val localPort: Int = 0,
    val connectTimeoutMs: Int = 3000,
    val failCooldownMs: Long = 30_000,
    val reprobeIntervalMs: Long = 60_000,
    /**
     * When no node can be reached, keep retrying (backoff with jitter) for this long while the game's socket
     * stays open, so the game sees a slow connect instead of an immediate failure. 0 = fail at once.
     */
    val connectRetryWindowMs: Long = 15_000,
    val retryMinMs: Long = 200,
    val retryMaxMs: Long = 3_000,
    /**
     * Close a connection when the game has sent data and nothing at all came back for this long, so the game
     * notices a dead path in seconds instead of minutes and reconnects. 0 disables. Do not use it for
     * protocols where the client legitimately sends for a long time without ever getting a reply.
     */
    val deadAfterUnansweredMs: Long = 20_000,
    val listener: ShieldListener? = null,
) {
    init {
        require(discovery != null || control != null || (nodes.isNotEmpty() && tokenProvider != null)) {
            "provide discovery, control, or both nodes and tokenProvider"
        }
    }
}
