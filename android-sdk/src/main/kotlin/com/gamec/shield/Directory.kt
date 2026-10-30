package com.gamec.shield

import android.content.Context
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

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

internal class NodeList(val nodes: List<Node>, val iat: Long, val exp: Long, val records: List<String>)

/**
 * Parses the signed node list published as DNS TXT records (see edge/cmd/signlist for the format).
 * Throws unless a complete record set verifies against [publicKeyB64] and has not expired.
 */
internal object ListVerifier {
    private val b64 = Base64.getUrlDecoder()
    private val recordRe = Regex("^[0-9]{1,3}/[0-9]{1,3}:")
    fun isRecord(r: String) = recordRe.containsMatchIn(r)

    fun parse(records: List<String>, publicKeyB64: String, nowSec: Long): NodeList {
        // part index -> data, grouped by the total the record claims; only complete groups are tried
        val groups = HashMap<Int, HashMap<Int, String>>()
        val dup = HashSet<Int>()
        for (r in records) {
            if (!isRecord(r)) continue
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
                val l = verify(body, publicKeyB64, nowSec, records.filter { isRecord(it) })
                if (best == null || l.iat > best.iat) best = l
            } catch (e: Exception) {
                lastError = e
            }
        }
        return best ?: throw lastError
    }

    private fun verify(body: String, publicKeyB64: String, nowSec: Long, used: List<String>): NodeList {
        val f = body.split(".", limit = 2)
        if (f.size != 2) throw IllegalArgumentException("malformed list")
        val payload = b64.decode(f[0])
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
        return NodeList(nodes, p.getLong("iat"), exp, used)
    }
}

/**
 * Keeps the newest verified node list. Refreshes on a timer, never accepts an older list than one already
 * seen (blocks replay of stale records), and keeps using the last good list until it really expires.
 */
internal class NodeDirectory(
    private val cfg: DiscoveryConfig,
    private val queryTxt: (String) -> List<String> = { Resolvers.query(cfg, it) },
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private var current: NodeList? = null
    private var nextTryAt = 0L

    init {
        try {
            val saved = cfg.store?.load().orEmpty()
            if (saved.isNotEmpty()) current = ListVerifier.parse(saved, cfg.publicKey, clock())
        } catch (_: Exception) {
            // a bad or expired saved list is simply not used
        }
    }

    @Synchronized
    fun get(): NodeList? {
        val now = clock()
        val c = current
        val usable = if (c != null && now <= c.exp) c else null
        if (now < nextTryAt) return usable
        try {
            val fresh = ListVerifier.parse(queryTxt(cfg.name), cfg.publicKey, now)
            if (c != null && fresh.iat < c.iat) throw SecurityException("older node list ignored")
            current = fresh
            nextTryAt = now + cfg.refreshSec
            try { cfg.store?.save(fresh.records) } catch (_: Exception) {}
            return fresh
        } catch (_: Exception) {
            nextTryAt = now + cfg.retrySec
            return usable
        }
    }
}
