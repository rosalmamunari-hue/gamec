package com.gamec.shield

import org.junit.After
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
    private var origin: ServerSocket? = null

    @Before
    fun setUp() {
        assumeTrue("GAMEC_TEST_PIN / GAMEC_TEST_SECRET not set", pin.isNotEmpty() && secret.isNotEmpty())
        val ss = ServerSocket(9000, 50, InetAddress.getByName(host))
        origin = ss
        Thread {
            while (!ss.isClosed) {
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
    }

    @After
    fun tearDown() {
        origin?.close()
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
