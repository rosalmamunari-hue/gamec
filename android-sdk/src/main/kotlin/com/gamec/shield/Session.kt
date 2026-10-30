package com.gamec.shield

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

internal class Session(val nodes: List<Node>, val token: String, val expiresAt: Long)

internal object SessionVerifier {
    /** Parses a control-service response; throws unless the ECDSA P-256 signature verifies. */
    fun parse(envelopeJson: String, publicKeyB64: String): Session {
        val env = JSONObject(envelopeJson)
        val payload = Base64.getDecoder().decode(env.getString("payload"))
        val sig = Base64.getDecoder().decode(env.getString("sig"))
        val pub = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64)))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub)
        v.update(payload)
        if (!v.verify(sig)) throw SecurityException("node list signature is invalid")

        val p = JSONObject(String(payload, Charsets.UTF_8))
        val arr = p.getJSONArray("nodes")
        val nodes = (0 until arr.length()).map {
            val n = arr.getJSONObject(it)
            Node(n.getString("host"), n.getInt("port"), n.getString("pin"))
        }
        if (nodes.isEmpty()) throw IllegalStateException("control returned an empty node list")
        return Session(nodes, p.getString("token"), p.getLong("expires_at"))
    }
}

internal fun httpFetch(cfg: ControlConfig): String {
    val conn = URL(cfg.url).openConnection() as HttpURLConnection
    try {
        conn.requestMethod = "POST"
        conn.connectTimeout = cfg.timeoutMs
        conn.readTimeout = cfg.timeoutMs
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.use { it.write("{\"device_id\":\"${cfg.deviceId}\"}".toByteArray()) }
        if (conn.responseCode != 200) throw IOException("control returned HTTP ${conn.responseCode}")
        return conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
    } finally {
        conn.disconnect()
    }
}

/**
 * Keeps one valid session. A new one is fetched when the token is about to expire; if the control
 * service is unreachable the previous session keeps being used until its token really expires.
 */
internal class SessionManager(
    private val cfg: ControlConfig,
    private val fetch: (ControlConfig) -> String = ::httpFetch,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private var current: Session? = null

    /** A usable session, or null if none can be had (control unreachable and nothing cached). */
    @Synchronized
    fun get(): Session? {
        val c = current
        val now = clock()
        if (c != null && c.expiresAt - cfg.refreshMarginSec > now) return c
        return try {
            refreshLocked()
        } catch (_: Exception) {
            if (c != null && c.expiresAt > now) c else null
        }
    }

    private fun refreshLocked(): Session {
        val s = SessionVerifier.parse(fetch(cfg), cfg.publicKey)
        current = s
        return s
    }
}
