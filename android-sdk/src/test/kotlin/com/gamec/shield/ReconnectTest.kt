package com.gamec.shield

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * Retry window, backoff and dead-connection detection, without any network: the "node" is a loopback server
 * the test controls, reached through a fake Connector.
 */
class ReconnectTest {
    private val node = Node("fake-node", 1, "pin")
    private val cleanup = ArrayList<AutoCloseable>()

    @After
    fun tearDown() {
        cleanup.forEach { try { it.close() } catch (_: Exception) {} }
    }

    private class Events : ShieldListener {
        val connected = CopyOnWriteArrayList<String>()
        val retrying = AtomicInteger()
        val failed = AtomicInteger()
        val lost = CopyOnWriteArrayList<String>()
        override fun onConnected(node: String) { connected += node }
        override fun onRetrying(attempt: Int) { retrying.incrementAndGet() }
        override fun onConnectFailed() { failed.incrementAndGet() }
        override fun onConnectionLost(reason: String) { lost += reason }
    }

    /** A loopback server standing in for the node/origin: echoes if [echo], otherwise swallows silently. */
    private fun remote(echo: Boolean): ServerSocket {
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        cleanup += ss
        Thread {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                cleanup += c
                Thread {
                    try {
                        val buf = ByteArray(1024)
                        while (true) {
                            val n = c.getInputStream().read(buf)
                            if (n < 0) break
                            if (echo) c.getOutputStream().write(buf, 0, n)
                        }
                    } catch (_: Exception) {
                    }
                }.also { it.isDaemon = true }.start()
            }
        }.also { it.isDaemon = true }.start()
        return ss
    }

    private fun client(
        connector: Connector,
        events: Events,
        window: Long = 5_000,
        deadAfter: Long = 0,
    ): Pair<ShieldClient, Int> {
        val cfg = ShieldConfig(
            listOf(node), { "tok" },
            connectRetryWindowMs = window, retryMinMs = 50, retryMaxMs = 200,
            deadAfterUnansweredMs = deadAfter, listener = events,
        )
        val shield = ShieldClient(cfg, cfg.toSource(), connector)
        cleanup += AutoCloseable { shield.stop() }
        return shield to shield.start()
    }

    private fun toRemote(r: ServerSocket) = Connector { _, _, _ -> Socket("127.0.0.1", r.localPort) }

    @Test
    fun keepsRetryingUntilTheNodeComesBack() {
        val r = remote(echo = true)
        val calls = AtomicInteger()
        val flaky = Connector { n, t, ms ->
            if (calls.incrementAndGet() <= 3) throw IOException("node down")
            toRemote(r).connect(n, t, ms)
        }
        val ev = Events()
        val (_, port) = client(flaky, ev)

        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 4000
            s.getOutputStream().write("ping".toByteArray())
            val buf = ByteArray(8)
            val n = s.getInputStream().read(buf)
            assertEquals("ping", String(buf, 0, n))
        }
        assertTrue("should have retried, got ${ev.retrying.get()}", ev.retrying.get() >= 1)
        assertEquals(1, ev.connected.size)
        assertEquals(0, ev.failed.get())
    }

    @Test
    fun gameSocketStaysOpenWhileRetrying() {
        val ev = Events()
        val (_, port) = client({ _, _, _ -> throw IOException("down") }, ev, window = 3_000)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 700
            try {
                val n = s.getInputStream().read()
                throw AssertionError("socket was closed early (read returned $n)")
            } catch (_: SocketTimeoutException) {
                // still open and waiting: what we want
            }
        }
    }

    @Test
    fun givesUpAfterTheRetryWindowAndClosesTheGameSocket() {
        val ev = Events()
        val (_, port) = client({ _, _, _ -> throw IOException("down") }, ev, window = 800)
        val t0 = System.currentTimeMillis()
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 5000
            assertEquals(-1, s.getInputStream().read())
        }
        val took = System.currentTimeMillis() - t0
        assertTrue("closed after ${took}ms, expected about the 800ms window", took in 600..3000)
        assertEquals(1, ev.failed.get())
        assertTrue(ev.retrying.get() >= 2)
    }

    @Test
    fun zeroWindowFailsImmediately() {
        val ev = Events()
        val (_, port) = client({ _, _, _ -> throw IOException("down") }, ev, window = 0)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 3000
            assertEquals(-1, s.getInputStream().read())
        }
        assertEquals(0, ev.retrying.get())
    }

    @Test
    fun aConnectionThatNeverAnswersIsClosedSoTheGameReconnects() {
        val ev = Events()
        val (_, port) = client(toRemote(remote(echo = false)), ev, deadAfter = 1_000)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 6000
            s.getOutputStream().write("hello?".toByteArray())
            val t0 = System.currentTimeMillis()
            assertEquals(-1, s.getInputStream().read())
            val took = System.currentTimeMillis() - t0
            assertTrue("closed after ${took}ms", took in 800..4000)
        }
        assertEquals(1, ev.lost.size)
    }

    @Test
    fun aConnectionThatKeepsAnsweringIsLeftAlone() {
        val ev = Events()
        val (_, port) = client(toRemote(remote(echo = true)), ev, deadAfter = 1_000)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 3000
            repeat(8) {
                s.getOutputStream().write("x".toByteArray())
                assertEquals('x'.code, s.getInputStream().read())
                Thread.sleep(300) // 2.4s in total, longer than deadAfter
            }
        }
        assertEquals(0, ev.lost.size)
    }

    @Test
    fun deadDetectionCanBeSwitchedOff() {
        val ev = Events()
        val (_, port) = client(toRemote(remote(echo = false)), ev, deadAfter = 0)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 2500
            s.getOutputStream().write("hello?".toByteArray())
            try {
                s.getInputStream().read()
                throw AssertionError("connection was closed although detection is off")
            } catch (_: SocketTimeoutException) {
            }
        }
        assertEquals(0, ev.lost.size)
    }

    @Test
    fun idleConnectionWithNothingSentIsNotTreatedAsDead() {
        val ev = Events()
        val (_, port) = client(toRemote(remote(echo = false)), ev, deadAfter = 500)
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 2000
            try {
                s.getInputStream().read()
                throw AssertionError("idle connection was closed")
            } catch (_: SocketTimeoutException) {
            }
        }
        assertEquals(0, ev.lost.size)
    }

    @Test
    fun stopDuringRetriesDoesNotThrowUncaught() {
        val uncaught = CopyOnWriteArrayList<Throwable>()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught += e }
        try {
            repeat(5) {
                val ev = Events()
                val (shield, port) = client({ _, _, _ -> throw IOException("down") }, ev, window = 10_000)
                Socket("127.0.0.1", port).use {
                    Thread.sleep(200)
                    shield.stop()
                    Thread.sleep(200)
                }
            }
            Thread.sleep(500)
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous)
        }
        assertTrue("uncaught: $uncaught", uncaught.isEmpty())
    }

    @Test
    fun listenerExceptionsDoNotBreakTheProxy() {
        val r = remote(echo = true)
        val bad = object : ShieldListener {
            override fun onConnected(node: String) { throw IllegalStateException("buggy game code") }
        }
        val cfg = ShieldConfig(listOf(node), { "tok" }, listener = bad)
        val shield = ShieldClient(cfg, cfg.toSource(), toRemote(r))
        cleanup += AutoCloseable { shield.stop() }
        val port = shield.start()
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 3000
            s.getOutputStream().write("a".toByteArray())
            assertEquals('a'.code, s.getInputStream().read())
        }
    }
}
