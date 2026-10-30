package com.gamec.shield

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Minimal DNS-over-HTTPS TXT lookup using the JSON API (Cloudflare, Google and others serve it). */
internal object Doh {
    const val CLOUDFLARE = "https://cloudflare-dns.com/dns-query"

    /** TXT values for [name] from the first provider that answers with at least one. */
    fun queryTxt(
        name: String,
        providers: List<String>,
        timeoutMs: Int,
        get: (url: String, timeoutMs: Int) -> String = ::httpGetDnsJson,
    ): List<String> {
        for (base in providers) {
            try {
                val url = base + "?name=" + URLEncoder.encode(name, "UTF-8") + "&type=TXT"
                val values = parse(get(url, timeoutMs))
                if (values.isNotEmpty()) return values
            } catch (_: Exception) {
                // try the next provider
            }
        }
        return emptyList()
    }

    fun parse(json: String): List<String> {
        val root = JSONObject(json)
        if (root.optInt("Status", -1) != 0) return emptyList()
        val answers = root.optJSONArray("Answer") ?: return emptyList()
        val out = ArrayList<String>()
        for (i in 0 until answers.length()) {
            val a = answers.getJSONObject(i)
            if (a.optInt("type") != 16) continue // 16 = TXT
            out += joinTxtStrings(a.getString("data"))
        }
        return out
    }

    /** A TXT value arrives as `"part1" "part2"` (one quoted string per 255 bytes); join the parts. */
    fun joinTxtStrings(data: String): String {
        val d = data.trim()
        if (!d.startsWith("\"")) return d
        val sb = StringBuilder()
        var inQuote = false
        var i = 0
        while (i < d.length) {
            val c = d[i]
            if (inQuote) {
                if (c == '\\' && i + 1 < d.length) {
                    sb.append(d[i + 1])
                    i += 2
                    continue
                }
                if (c == '"') inQuote = false else sb.append(c)
            } else if (c == '"') {
                inQuote = true
            }
            i++
        }
        return sb.toString()
    }
}

internal fun httpGetDnsJson(url: String, timeoutMs: Int): String {
    val conn = URL(url).openConnection() as HttpURLConnection
    try {
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.setRequestProperty("accept", "application/dns-json")
        if (conn.responseCode != 200) throw java.io.IOException("DoH returned HTTP ${conn.responseCode}")
        return conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
    } finally {
        conn.disconnect()
    }
}
