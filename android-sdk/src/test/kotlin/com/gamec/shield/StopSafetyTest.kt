package com.gamec.shield

import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * stop() interrupts worker threads. On Android an exception escaping a thread kills the whole app, so none
 * may escape. Needs no edge node: the fake node accepts TCP and then stalls, which keeps workers busy.
 */
class StopSafetyTest {
    private fun stalledNode(): Pair<ServerSocket, Node> {
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val held = CopyOnWriteArrayList<Socket>()
        Thread {
            while (!ss.isClosed) {
                try { held += ss.accept() } catch (_: Exception) { break }
            }
        }.also { it.isDaemon = true }.start()
        return ss to Node("127.0.0.1", ss.localPort, "pin")
    }

    @Test
    fun stoppingWhileWorkersAreBusyDoesNotThrowUncaught() {
        val (ss, node) = stalledNode()
        val uncaught = CopyOnWriteArrayList<Throwable>()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught += e }
        try {
            repeat(5) {
                val shield = ShieldClient(ShieldConfig(listOf(node), { "tok" }, connectTimeoutMs = 1500))
                val port = shield.start()
                // a game connection whose relay is stuck in the TLS handshake with the stalled node
                Socket("127.0.0.1", port).use {
                    Thread.sleep(250)
                    shield.stop()
                    Thread.sleep(250)
                }
            }
            Thread.sleep(2000) // let blocked workers hit their timeouts
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous)
            ss.close()
        }
        assertTrue("uncaught exceptions would crash an Android app: $uncaught", uncaught.isEmpty())
    }
}
