package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Pure JVM tests for signature checking and session caching; no network or edge node needed. */
class SessionManagerTest {
    private val enc = Base64.getEncoder()

    private fun newKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun pub(k: KeyPair) = enc.encodeToString(k.public.encoded)

    private fun payload(token: String = "tok", expiresAt: Long = 1000, pin: String = "pinA") =
        """{"nodes":[{"host":"10.0.0.1","port":30800,"pin":"$pin"}],"token":"$token","issued_at":0,"expires_at":$expiresAt}"""

    private fun envelope(key: KeyPair, payloadJson: String): String {
        val raw = payloadJson.toByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(raw)
            sign()
        }
        return """{"payload":"${enc.encodeToString(raw)}","sig":"${enc.encodeToString(sig)}"}"""
    }

    private fun cfg(key: KeyPair) = ControlConfig("http://unused", pub(key), "device-1234567890abcdef", refreshMarginSec = 60)

    @Test
    fun validEnvelopeParses() {
        val k = newKey()
        val s = SessionVerifier.parse(envelope(k, payload()), pub(k))
        assertEquals("tok", s.token)
        assertEquals(Node("10.0.0.1", 30800, "pinA"), s.nodes.single())
        assertEquals(1000L, s.expiresAt)
    }

    @Test
    fun tamperedPayloadIsRejected() {
        val k = newKey()
        val good = envelope(k, payload(pin = "pinA"))
        // swap the node pin inside the signed payload but keep the old signature
        val evil = enc.encodeToString(payload(pin = "pinX").toByteArray())
        val sig = Regex("\"sig\":\"([^\"]+)\"").find(good)!!.groupValues[1]
        try {
            SessionVerifier.parse("""{"payload":"$evil","sig":"$sig"}""", pub(k))
            fail("a modified node list must not verify")
        } catch (_: SecurityException) {
        }
    }

    @Test
    fun responseSignedByAnotherKeyIsRejected() {
        val attacker = newKey()
        val real = newKey()
        try {
            SessionVerifier.parse(envelope(attacker, payload()), pub(real))
            fail("signature from a different key must not verify")
        } catch (_: SecurityException) {
        }
    }

    @Test
    fun sessionIsCachedUntilNearExpiry() {
        val k = newKey()
        var now = 100L
        var fetches = 0
        val m = SessionManager(cfg(k), fetch = { fetches++; envelope(k, payload(expiresAt = 400)) }, clock = { now })
        val first = m.get()
        assertNotNull(first)
        assertSame(first, m.get())
        assertEquals(1, fetches)

        now = 339 // 61s left: still outside the 60s refresh margin
        assertSame(first, m.get())
        assertEquals(1, fetches)

        now = 341 // 59s left: refresh
        m.get()
        assertEquals(2, fetches)
    }

    @Test
    fun staleSessionIsUsedWhileControlIsDown() {
        val k = newKey()
        var now = 100L
        var down = false
        val m = SessionManager(
            cfg(k),
            fetch = { if (down) throw java.io.IOException("control unreachable") else envelope(k, payload(expiresAt = 400)) },
            clock = { now },
        )
        val first = m.get()
        down = true
        now = 350 // inside the refresh margin but the token is still valid
        assertSame(first, m.get())
    }

    @Test
    fun noSessionOnceExpiredAndControlIsDown() {
        val k = newKey()
        var now = 100L
        var down = false
        val m = SessionManager(
            cfg(k),
            fetch = { if (down) throw java.io.IOException("control unreachable") else envelope(k, payload(expiresAt = 400)) },
            clock = { now },
        )
        m.get()
        down = true
        now = 401
        assertNull(m.get())
    }

    @Test
    fun badSignatureNeverBecomesTheCurrentSession() {
        val k = newKey()
        val m = SessionManager(cfg(k), fetch = { envelope(newKey(), payload()) }, clock = { 100L })
        assertNull(m.get())
    }

    @Test
    fun deviceIdIsValidated() {
        try {
            ControlConfig("http://x", "k", "has.dots.and.is.long.enough.123")
            fail("device id with illegal characters must be rejected")
        } catch (_: IllegalArgumentException) {
        }
    }
}
