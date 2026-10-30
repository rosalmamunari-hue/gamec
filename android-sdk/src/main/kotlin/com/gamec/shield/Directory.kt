package com.gamec.shield

import android.content.Context
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Where the last good record set is kept so the app can start while DNS is unreachable. */
interface ListStore {
    fun load(): List<String>
    fun save(records: List<String>)
}

class PrefsListStore(context: Context) : ListStore {
    private val prefs = context.getSharedPreferences("gamec_shield_list", Context.MODE_PRIVATE)
    override fun load(): List<String> = prefs.getStringSet("records", emptySet())!!.toList()
    override fun save(records: List<String>) {
        prefs.edit().putStringSet("records", records.toSet()).apply()
    }
}

internal class NodeList(
    val nodes: List<Node>, val iat: Long, val exp: Long, val records: List<String>,
    /** Names the panel says to read from next time; the ones built into the app are then only a fallback. */
    val next: List<String> = emptyList(),
)

/**
 * Parses the signed node list published as DNS TXT records (see edge/cmd/signlist for the format).
 * Throws unless a complete record set verifies against [publicKeyB64] and has not expired.
 */
internal object ListVerifier {
    private val b64 = Base64.getUrlDecoder()
    private val recordRe = Regex("^[0-9]{1,3}/[0-9]{1,3}:")
    private val bareRe = Regex("^[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}$")
    fun isRecord(r: String) = recordRe.containsMatchIn(r) || bareRe.matches(r)

    fun parse(records: List<String>, publicKeyB64: String, nowSec: Long, listKeyB64: String? = null): NodeList {
        // part index -> data, grouped by the total the record claims; only complete groups are tried
        val groups = HashMap<Int, HashMap<Int, String>>()
        val dup = HashSet<Int>()
        for (r in records) {
            if (!isRecord(r)) continue
            if (bareRe.matches(r)) { // the whole list in one record
                val g = groups.getOrPut(1) { HashMap() }
                if (g.put(1, r) != null) dup.add(1)
                continue
            }
            val f = r.split(":", limit = 2)
            if (f.size != 2) continue
            val pos = f[0].split("/")
            val i = pos.getOrNull(0)?.toIntOrNull() ?: continue
            val n = pos.getOrNull(1)?.toIntOrNull() ?: continue
            if (pos.size != 2 || i < 1 || i > n) continue
            val g = groups.getOrPut(n) { HashMap() }
            if (g.put(i, f[1]) != null) dup.add(n) // two different versions share this shape: ambiguous
        }

        var best: NodeList? = null
        var lastError: Exception = IllegalStateException("no list records")
        for ((n, parts) in groups) {
            if (n in dup || parts.size != n) continue
            try {
                val body = (1..n).joinToString("") { parts[it]!! }
                val l = verify(body, publicKeyB64, nowSec, records.filter { isRecord(it) }, listKeyB64)
                if (best == null || l.iat > best.iat) best = l
            } catch (e: Exception) {
                lastError = e
            }
        }
        return best ?: throw lastError
    }

    /** nonce(12) || ciphertext || tag, AES-256-GCM; null when [data] is not sealed with [keyB64]. */
    private fun unseal(data: ByteArray, keyB64: String): ByteArray? {
        if (data.size <= 12 + 16) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(Base64.getDecoder().decode(keyB64), "AES"), GCMParameterSpec(128, data, 0, 12))
            c.doFinal(data, 12, data.size - 12)
        } catch (_: Exception) {
            null
        }
    }

    private fun verify(body: String, publicKeyB64: String, nowSec: Long, used: List<String>, listKeyB64: String?): NodeList {
        val f = body.split(".", limit = 2)
        if (f.size != 2) throw IllegalArgumentException("malformed list")
        val first = b64.decode(f[0])
        // an unsealed list simply fails to decrypt and is checked as it is: the signature decides
        val payload = (if (listKeyB64 != null) unseal(first, listKeyB64) else null) ?: first
        val sig = b64.decode(f[1])
        val pub = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64)))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub)
        v.update(payload)
        if (!v.verify(sig)) throw SecurityException("node list signature is invalid")

        val p = JSONObject(String(payload, Charsets.UTF_8))
        if (p.getInt("v") != 1) throw IllegalArgumentException("unsupported list version")
        val exp = p.getLong("exp")
        if (nowSec > exp) throw IllegalStateException("node list expired")
        val arr = p.getJSONArray("nodes")
        val nodes = (0 until arr.length()).map {
            val n = arr.getJSONObject(it)
            Node(n.getString("h"), n.getInt("p"), n.getString("k"))
        }
        if (nodes.isEmpty()) throw IllegalStateException("empty node list")
        val next = p.optJSONArray("next")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        return NodeList(nodes, p.getLong("iat"), exp, used, next)
    }
}

/**
 * Keeps the newest verified node list. Refreshes on a timer, never accepts an older list than one already
 * seen (blocks replay of stale records), and keeps using the last good list until it really expires.
 */
internal class NodeDirectory(
    private val cfg: DiscoveryConfig,
    /** For tests; null = the real resolvers. */
    private val queryTxt: ((String) -> List<String>)? = null,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private var current: NodeList? = null
    private var nextTryAt = 0L
    private var lastTryAt = Long.MIN_VALUE / 2

    init {
        try {
            val saved = cfg.store?.load().orEmpty()
            if (saved.isNotEmpty()) current = ListVerifier.parse(saved, cfg.publicKey, clock(), cfg.listKey)
        } catch (_: Exception) {
            // a bad or expired saved list is simply not used
        }
    }

    @Synchronized
    fun get(): NodeList? {
        val now = clock()
        if (now < nextTryAt) return usable(now)
        return fetch(now)
    }

    /** Re-read now because nothing worked; at most once per [DiscoveryConfig.urgentRefreshSec]. */
    @Synchronized
    fun refreshNow(): NodeList? {
        val now = clock()
        if (now - lastTryAt < cfg.urgentRefreshSec) return usable(now)
        return fetch(now)
    }

    /** The names the last good list pointed to come first; the ones built into the app are the fallback. */
    private fun names(): List<String> =
        ((current?.next ?: emptyList()) + cfg.name + cfg.fallbackNames).distinct()

    private fun usable(now: Long): NodeList? = current?.takeIf { now <= it.exp }

    private fun fetch(now: Long): NodeList? {
        lastTryAt = now
        val c = current
        try {
            var fresh: NodeList? = null
            for (n in names()) {
                try {
                    val recs = queryTxt?.invoke(n) ?: Resolvers.query(cfg, n, c?.iat ?: 0)
                    val f = ListVerifier.parse(recs, cfg.publicKey, now, cfg.listKey)
                    if (c != null && f.iat < c.iat) continue // stale copy at this name; try the next
                    fresh = f
                    break
                } catch (_: Exception) {
                    // unreadable or forged at this name; try the next
                }
            }
            if (fresh == null) throw SecurityException("no name gave a usable node list")
            current = fresh
            nextTryAt = now + cfg.refreshSec
            try { cfg.store?.save(fresh.records) } catch (_: Exception) {}
            return fresh
        } catch (_: Exception) {
            nextTryAt = now + cfg.retrySec
            return usable(now)
        }
    }
}
