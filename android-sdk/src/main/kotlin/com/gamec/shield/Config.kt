package com.gamec.shield

/** An edge node. [pinSha256] is base64(SHA-256(SubjectPublicKeyInfo)) of the node's certificate. */
data class Node(val host: String, val port: Int, val pinSha256: String) {
    override fun toString() = "$host:$port"
}

class ShieldConfig(
    val nodes: List<Node>,
    /** Returns a fresh token issued by your login server (the HMAC secret must never ship in the app). */
    val tokenProvider: () -> String,
    /** Local port the game connects to instead of the real server. 0 = pick a free port. */
    val localPort: Int = 0,
    val connectTimeoutMs: Int = 3000,
    val failCooldownMs: Long = 30_000,
    val reprobeIntervalMs: Long = 60_000,
)
