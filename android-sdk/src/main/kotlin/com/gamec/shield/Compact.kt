package com.gamec.shield

import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The compact list format (edge/shieldlist/compact.go). A record is base64url (no padding) of
 * signature(64, r||s) || content; content is the payload, or nonce(12) || AES-256-GCM(payload) when sealed.
 * The signature is ECDSA P-256 over SHA-256([DOMAIN] || payload). Payload: version(1)=2 kind(1) iat(4)
 * exp(4) count(1) entries; kind 1 = nodes (family(1) address(4|16) port(2) pin(16)), kind 2 = the names
 * to read from next time (length(1) name). Values that do not verify (SPF, other people's records) are skipped.
 */
internal object Compact {
    private const val DOMAIN = "gamec compact list v2\u0000"
    private const val SIG = 64
    private const val HEAD = 11
    const val KIND_LIST = 1
    const val KIND_NEXT = 2
    /** The label in front of a list's name where its next names are published. */
    const val NEXT_LABEL = "dw2"

    private val shape = Regex("^[A-Za-z0-9_-]+$")
    fun looksCompact(v: String) = v.length in 100..4000 && shape.matches(v)

    fun nextName(name: String) = "$NEXT_LABEL." + name.trimEnd('.')

    class Opened(val kind: Int, val iat: Long, val exp: Long, val count: Int, val entries: ByteArray)

    /** Checks one value; returns its payload if it is of [kind] and signed by [publicKeyB64], else null. */
    fun open(v: String, publicKeyB64: String, listKeyB64: String?, kind: Int): Opened? {
        if (!looksCompact(v)) return null
        val body = try { Base64.getUrlDecoder().decode(v) } catch (_: Exception) { return null }
        if (body.size < SIG + HEAD) return null
        val sig = body.copyOfRange(0, SIG)
        val content = body.copyOfRange(SIG, body.size)
        // an unsealed record simply fails to decrypt and is checked as it is: the signature decides
        val payload = (if (listKeyB64 != null) unseal(content, listKeyB64) else null) ?: content
        val v1 = Signature.getInstance("SHA256withECDSA")
        v1.initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64))))
        v1.update(DOMAIN.toByteArray(Charsets.ISO_8859_1))
        v1.update(payload)
        if (!v1.verify(der(sig))) return null
        if (payload.size < HEAD || payload[0].toInt() != 2 || payload[1].toInt() != kind) return null
        val b = ByteBuffer.wrap(payload)
        val iat = b.getInt(2).toLong() and 0xffffffffL
        val exp = b.getInt(6).toLong() and 0xffffffffL
        return Opened(kind, iat, exp, payload[10].toInt() and 0xff, payload.copyOfRange(HEAD, payload.size))
    }

    /** The nodes of a verified list payload, or null if it is malformed. */
    fun nodes(o: Opened): List<Node>? {
        val out = ArrayList<Node>()
        var i = 0
        val e = o.entries
        repeat(o.count) {
            if (i >= e.size) return null
            val size = when (e[i].toInt()) { 4 -> 4; 6 -> 16; else -> return null }
            if (i + 1 + size + 2 + 16 > e.size) return null
            val host = InetAddress.getByAddress(e.copyOfRange(i + 1, i + 1 + size)).hostAddress ?: return null
            val port = ((e[i + 1 + size].toInt() and 0xff) shl 8) or (e[i + 2 + size].toInt() and 0xff)
            val pin = Base64.getEncoder().encodeToString(e.copyOfRange(i + 3 + size, i + 3 + size + 16))
            out += Node(host, port, pin)
            i += 1 + size + 2 + 16
        }
        return if (i == e.size && out.isNotEmpty()) out else null
    }

    /** The names of a verified next-names payload, or null if it is malformed. */
    fun names(o: Opened): List<String>? {
        val out = ArrayList<String>()
        var i = 0
        val e = o.entries
        repeat(o.count) {
            if (i >= e.size) return null
            val len = e[i].toInt() and 0xff
            if (i + 1 + len > e.size) return null
            out += String(e, i + 1, len, Charsets.US_ASCII)
            i += 1 + len
        }
        return if (i == e.size && out.isNotEmpty()) out else null
    }

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

    /** r||s (32 bytes each) as the DER SEQUENCE that java.security.Signature expects. */
    private fun der(sig: ByteArray): ByteArray {
        fun int(x: ByteArray): ByteArray {
            var i = 0
            while (i < x.size - 1 && x[i].toInt() == 0) i++
            var v = x.copyOfRange(i, x.size)
            if (v[0] < 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = int(sig.copyOfRange(0, 32)) + int(sig.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}

/** The signed names to read the list from next time, published at dw2.<name>. */
internal class NextNames(val names: List<String>, val iat: Long, val exp: Long, val records: List<String>)

internal object NextVerifier {
    /** The newest valid next-names record among [records]; throws if there is none. */
    fun parse(records: List<String>, publicKeyB64: String, nowSec: Long, listKeyB64: String?): NextNames {
        var best: NextNames? = null
        for (r in records) {
            val o = Compact.open(r, publicKeyB64, listKeyB64, Compact.KIND_NEXT) ?: continue
            val names = Compact.names(o) ?: continue
            if (nowSec > o.exp) continue
            if (best == null || o.iat > best.iat) best = NextNames(names, o.iat, o.exp, listOf(r))
        }
        return best ?: throw IllegalStateException("no valid next names")
    }
}
