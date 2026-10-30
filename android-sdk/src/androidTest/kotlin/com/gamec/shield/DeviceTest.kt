package com.gamec.shield

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.Socket
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Runs on a real Android runtime (Conscrypt TLS, real Context). Needs a reachable edge node and control
 * service; pass them with `am instrument -e pin .. -e secret .. -e nodeHost .. -e controlUrl .. -e controlKey ..`.
 */
@RunWith(AndroidJUnit4::class)
class DeviceTest {
    private val args = InstrumentationRegistry.getArguments()
    private val nodeHost = args.getString("nodeHost") ?: "10.0.2.2"
    private val nodePort = (args.getString("nodePort") ?: "30800").toInt()
    private val pin = args.getString("pin") ?: ""
    private val secret = args.getString("secret") ?: ""
    private val controlUrl = args.getString("controlUrl") ?: ""
    private val controlKey = args.getString("controlKey") ?: ""

    private fun node() = Node(nodeHost, nodePort, pin)

    private fun requireNode() = assumeTrue("pin not given", pin.isNotEmpty())
    private fun requireControl() =
        assumeTrue("control args not given", controlUrl.isNotEmpty() && controlKey.isNotEmpty())

    private fun token(key: String): String {
        val body = "device." + System.currentTimeMillis() / 1000
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        return body + "." + mac.doFinal(body.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    /** Sends "ping" through the local proxy; returns the reply, or null if the connection was closed. */
    private fun pingVia(proxyPort: Int): String? =
        Socket("127.0.0.1", proxyPort).use { s ->
            s.soTimeout = 8000
            s.getOutputStream().write("ping".toByteArray())
            s.getOutputStream().flush()
            try {
                val buf = ByteArray(16)
                val n = s.getInputStream().read(buf)
                if (n <= 0) null else String(buf, 0, n)
            } catch (_: java.net.SocketException) {
                null
            }
        }

    @Test
    fun tlsIs13OnThisAndroid() {
        requireNode()
        PinnedTls.connect(node(), 5000).use { s ->
            assertEquals("TLSv1.3", s.session.protocol)
        }
    }

    @Test
    fun wrongPinIsRefusedOnThisAndroid() {
        requireNode()
        try {
            PinnedTls.connect(Node(nodeHost, nodePort, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 5000).close()
            fail("a wrong pin must be refused")
        } catch (_: Exception) {
        }
    }

    @Test
    fun fixedNodeValidTokenRelays() {
        requireNode()
        assumeTrue("secret not given", secret.isNotEmpty())
        val shield = ShieldClient(ShieldConfig(listOf(node()), { token(secret) }))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun fixedNodeBadTokenIsNotRelayed() {
        requireNode()
        val shield = ShieldClient(ShieldConfig(listOf(node()), { token("wrong-secret") }))
        val p = shield.start()
        try {
            assertNull(pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun failoverSkipsDeadNode() {
        requireNode()
        assumeTrue("secret not given", secret.isNotEmpty())
        val dead = Node(nodeHost, 1, pin)
        val shield = ShieldClient(ShieldConfig(listOf(dead, node()), { token(secret) }))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun controlModeFetchesEverythingAutomatically() {
        requireControl()
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val shield = ShieldClient(ShieldConfig(control = ControlConfig(controlUrl, controlKey, DeviceId.getOrCreate(ctx))))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun controlModeRefusesAServiceSignedByTheWrongKey() {
        requireControl()
        val other = java.security.KeyPairGenerator.getInstance("EC")
            .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val wrong = java.util.Base64.getEncoder().encodeToString(other.public.encoded)
        val shield = ShieldClient(ShieldConfig(control = ControlConfig(controlUrl, wrong, "device-wrong-key-0000001"), connectRetryWindowMs = 0))
        val p = shield.start()
        try {
            assertNull(pingVia(p))
        } finally {
            shield.stop()
        }
    }

    @Test
    fun discoveryModeWorksOnThisAndroid() {
        val doh = args.getString("dohUrl") ?: ""
        val listKey = args.getString("listKey") ?: ""
        assumeTrue("discovery args not given", doh.isNotEmpty() && listKey.isNotEmpty())
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val cfg = DiscoveryConfig("_gs.example.com", listKey, DeviceId.getOrCreate(ctx),
            dohProviders = listOf(doh), store = PrefsListStore(ctx))
        val shield = ShieldClient(ShieldConfig(discovery = cfg))
        val p = shield.start()
        try {
            assertEquals("ping", pingVia(p))
        } finally {
            shield.stop()
        }
    }

    /**
     * The whole production path: real DoH, real signed TXT records, real nodes, real origin. Only runs when
     * `-e liveName <dns name> -e liveKey <public key>` is given. The origin is not an echo server, so success
     * means the relay stays open (the node dials the origin only after accepting the token and closes the
     * connection if that fails), and it reports how long each stage took.
     */
    @Test
    fun liveChainThroughRealDnsAndRealNodes() {
        val name = args.getString("liveName") ?: ""
        val key = args.getString("liveKey") ?: ""
        assumeTrue("live args not given", name.isNotEmpty() && key.isNotEmpty())
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val cfg = DiscoveryConfig(name, key, DeviceId.getOrCreate(ctx), store = PrefsListStore(ctx))

        val t0 = System.nanoTime()
        val list = NodeDirectory(cfg).get()
        val dnsMs = (System.nanoTime() - t0) / 1_000_000
        assertTrue("no verified node list from real DNS", list != null && list.nodes.isNotEmpty())
        android.util.Log.i("GamecLive", "DNS+verify: ${dnsMs}ms, nodes=${list!!.nodes}")

        val shield = ShieldClient(ShieldConfig(discovery = cfg))
        val p = shield.start()
        try {
            val t1 = System.nanoTime()
            Socket("127.0.0.1", p).use { s ->
                s.soTimeout = 4000
                // give the relay time to fetch a token, connect, and for the node to dial the origin
                try {
                    val n = s.getInputStream().read(ByteArray(16))
                    assertTrue("relay closed (EOF) instead of staying open", n != -1)
                    android.util.Log.i("GamecLive", "origin sent $n bytes after ${(System.nanoTime() - t1) / 1_000_000}ms")
                } catch (_: java.net.SocketTimeoutException) {
                    android.util.Log.i("GamecLive", "relay open and quiet for 4s (origin waits for the client)")
                }
            }
        } finally {
            shield.stop()
        }
    }

    @Test
    fun deviceIdIsStableAndValid() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val a = DeviceId.getOrCreate(ctx)
        val b = DeviceId.getOrCreate(ctx)
        assertEquals(a, b)
        assertTrue(Regex("^[A-Za-z0-9_-]{16,64}$").matches(a))
    }
}
