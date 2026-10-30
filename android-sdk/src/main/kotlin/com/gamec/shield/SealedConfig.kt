package com.gamec.shield

import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The names and keys of a [DiscoveryConfig] packed into one opaque string (made with
 * `signlist -seal-config <passphrase> -name ... -pub ...`), so they are not in the app package as plain text.
 * The passphrase ships in the app too: this stops casual scraping (grep, "strings"), not someone who reverses it.
 *
 *     val o = SealedConfig.open(BLOB, PASSPHRASE)
 *     DiscoveryConfig(o.name, o.publicKey, deviceId, listKey = o.listKey, fallbackNames = o.fallbackNames, store = ...)
 */
class SealedConfig private constructor(
    val name: String,
    val fallbackNames: List<String>,
    val publicKey: String,
    val listKey: String?,
) {
    companion object {
        /** Throws if the passphrase is wrong or the string is damaged. */
        fun open(blob: String, passphrase: String): SealedConfig {
            val raw = Base64.getUrlDecoder().decode(blob)
            require(raw.size > 12 + 16) { "config too short" }
            val key = MessageDigest.getInstance("SHA-256").digest("gamec-config\u0000$passphrase".toByteArray())
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, raw, 0, 12))
            val j = JSONObject(String(c.doFinal(raw, 12, raw.size - 12), Charsets.UTF_8))
            val f = j.optJSONArray("f")
            return SealedConfig(
                j.getString("n"),
                if (f == null) emptyList() else (0 until f.length()).map { f.getString(it) },
                j.getString("k"),
                j.optString("l").ifEmpty { null },
            )
        }
    }
}
