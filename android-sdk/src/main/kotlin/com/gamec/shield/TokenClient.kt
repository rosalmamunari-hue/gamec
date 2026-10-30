package com.gamec.shield

import org.json.JSONObject
import java.io.DataInputStream

internal class IssuedToken(val token: String, val expiresAt: Long)

/** Asks an edge node for a token: one TLS connection, one "GET-TOKEN <device id>" frame, one JSON frame back. */
internal object TokenClient {
    fun request(node: Node, deviceId: String, timeoutMs: Int): IssuedToken {
        val s = PinnedTls.connect(node, timeoutMs)
        try {
            s.soTimeout = timeoutMs
            val msg = "GET-TOKEN $deviceId".toByteArray()
            val out = s.outputStream
            out.write(byteArrayOf((msg.size shr 8).toByte(), msg.size.toByte()))
            out.write(msg)
            out.flush()

            val inp = DataInputStream(s.inputStream)
            val len = inp.readUnsignedShort()
            if (len == 0 || len > 1024) throw java.io.IOException("bad token reply length $len")
            val body = ByteArray(len)
            inp.readFully(body)
            val j = JSONObject(String(body, Charsets.UTF_8))
            return IssuedToken(j.getString("token"), j.getLong("expires_at"))
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }
}

/** Keeps one valid token, asking the given nodes in order when the cached one is about to expire. */
internal class TokenManager(
    private val deviceId: String,
    private val marginSec: Long,
    private val timeoutMs: Int,
    private val request: (Node, String, Int) -> IssuedToken = TokenClient::request,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private var current: IssuedToken? = null

    @Synchronized
    fun get(nodesInOrder: List<Node>): String? {
        val now = clock()
        val c = current
        if (c != null && c.expiresAt - marginSec > now) return c.token
        for (node in nodesInOrder) {
            try {
                val t = request(node, deviceId, timeoutMs)
                current = t
                return t.token
            } catch (_: Exception) {
                // next node
            }
        }
        return if (c != null && c.expiresAt > now) c.token else null
    }
}
