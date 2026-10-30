package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-end tests against a locally started edge node (see .github/workflows/ci.yml).
 * Skipped unless GAMEC_TEST_PIN and GAMEC_TEST_SECRET are set. The edge forwards to 127.0.0.1:9000,
 * where this class runs an echo server.
 */
class ShieldTest {
    private val host = "127.0.0.1"
    private val port = 30800
    private val pin = System.getenv("GAMEC_TEST_PIN") ?: ""
    private val secret = System.getenv("GAMEC_TEST_SECRET") ?: ""

    @Before
    fun setUp() {
        assumeTrue("GAMEC_TEST_PIN / GAMEC_TEST_SECRET not set", pin.isNotEmpty() && secret.isNotEmpty())
        EchoOrigin.ensureStarted()
    }

    /** Same format the edge checks: "<uid>.<unix ts>.<hex hmac-sha256(secret, uid.ts)>" */
    private fun token(key: String): String {
        val body = "android." + System.currentTimeMillis() / 1000
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        val hex = mac.doFinal(body.toByteArray()).joinToString("") { "%02x".format(it) }
        return "$body.$hex"
    }

    private fun goodNode() = Node(host, port, pin)

    /** Sends "ping" through the local proxy; returns the reply, or null if the connection was closed. */
    private fun pingVia(proxyPort: Int): String? {
        Socket(host, proxyPort).use { s ->
            s.soTimeout = 6000
            s.getOutputStream().write("ping".toByteArray())
            s.getOutputStream().flush()
            return try {
                val buf = ByteArray(16)
                val n = s.getInputStream().read(buf)
                if (n <= 0) null else String(buf, 0, n)
            } catch (_: java.net.SocketException) {
                null
            }
        }
    }

    @Test
    fun correctPinIsAccepted() {
        PinnedTls.connect(goodNode(), 5000).close()
    }

    @Test
    fun wrongPinIsRefused() {
        try {
            PinnedTls.connect(Node(host, port, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 5000).close()
            fail("a wrong pin must be refused")
        } catch (e: Exception) {
            // expected: pin mismatch surfaces as a TLS handshake failure
        }
    }

    @Test
    fun validTokenRelaysToOrigin() {
        val shield = ShieldClient(ShieldConfig(listOf(goodNode()), { token(secret) }))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun badTokenIsNotRelayed() {
        val shield = ShieldClient(ShieldConfig(listOf(goodNode()), { token("wrong-secret") }))
        val p = shield.start()
        try {
            assertEquals(null, pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun controlModeFetchesTokenAndNodesAutomatically() {
        val url = System.getenv("GAMEC_TEST_CONTROL_URL")
        val key = System.getenv("GAMEC_TEST_CONTROL_PUBKEY")
        assumeTrue("control env not set", !url.isNullOrEmpty() && !key.isNullOrEmpty())
        val shield = ShieldClient(ShieldConfig(control = ControlConfig(url!!, key!!, "device-android-e2e-0001")))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun controlModeRefusesAServiceSignedByTheWrongKey() {
        val url = System.getenv("GAMEC_TEST_CONTROL_URL")
        assumeTrue("control env not set", !url.isNullOrEmpty())
        val other = java.security.KeyPairGenerator.getInstance("EC")
            .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val wrongKey = java.util.Base64.getEncoder().encodeToString(other.public.encoded)
        val shield = ShieldClient(ShieldConfig(control = ControlConfig(url!!, wrongKey, "device-android-e2e-0002")))
        val p = shield.start()
        try {
            assertEquals(null, pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun failoverSkipsDeadNode() {
        val dead = Node(host, 1, pin)
        val shield = ShieldClient(ShieldConfig(listOf(dead, goodNode()), { token(secret) }))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }
}

/** Echo server on 127.0.0.1:9000, started once and kept for the whole test JVM (rebinding per test races on the port). */
private object EchoOrigin {
    private var started = false

    @Synchronized
    fun ensureStarted() {
        if (started) return
        val ss = ServerSocket(9000, 50, InetAddress.getByName("127.0.0.1"))
        Thread {
            while (true) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                Thread {
                    try {
                        val buf = ByteArray(4096)
                        while (true) {
                            val n = c.getInputStream().read(buf)
                            if (n < 0) break
                            c.getOutputStream().write(buf, 0, n)
                        }
                    } catch (_: Exception) {
                    } finally {
                        c.close()
                    }
                }.start()
            }
        }.also { it.isDaemon = true }.start()
        started = true
    }
}
