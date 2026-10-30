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
 * Either give a [control] (recommended: tokens and nodes are fetched and kept fresh automatically),
 * or a fixed [nodes] list plus a [tokenProvider] you implement yourself.
 */
class ShieldConfig(
    val nodes: List<Node> = emptyList(),
    /** Returns a fresh token issued by your own backend (the HMAC secret must never ship in the app). */
    val tokenProvider: (() -> String)? = null,
    val control: ControlConfig? = null,
    /** Local port the game connects to instead of the real server. 0 = pick a free port. */
    val localPort: Int = 0,
    val connectTimeoutMs: Int = 3000,
    val failCooldownMs: Long = 30_000,
    val reprobeIntervalMs: Long = 60_000,
) {
    init {
        require(control != null || (nodes.isNotEmpty() && tokenProvider != null)) {
            "provide either control, or both nodes and tokenProvider"
        }
    }
}
