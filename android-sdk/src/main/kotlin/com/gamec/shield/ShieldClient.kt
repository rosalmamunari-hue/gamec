package com.gamec.shield

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local TCP proxy. The game connects to 127.0.0.1:[ShieldClient.start] result; each connection is relayed
 * over pinned TLS 1.3 to the fastest healthy edge node, which forwards to the hidden origin.
 *
 *   val shield = ShieldClient(ShieldConfig(nodes, { fetchTokenFromLoginServer() }))
 *   val port = shield.start()
 *   // point the game socket at 127.0.0.1:port
 */
class ShieldClient(private val cfg: ShieldConfig) {
    private val selector = NodeSelector(cfg.nodes, cfg.failCooldownMs)
    private val pool = Executors.newCachedThreadPool()
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null

    fun start(): Int {
        check(running.compareAndSet(false, true)) { "already started" }
        val ss = ServerSocket(cfg.localPort, 50, InetAddress.getByName("127.0.0.1"))
        server = ss
        pool.execute {
            try {
                while (running.get()) {
                    selector.probeAll(cfg.connectTimeoutMs)
                    var waited = 0L
                    while (running.get() && waited < cfg.reprobeIntervalMs) {
                        Thread.sleep(500)
                        waited += 500
                    }
                }
            } catch (_: InterruptedException) {
            }
        }
        pool.execute {
            while (running.get()) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                pool.execute { relay(c) }
            }
        }
        return ss.localPort
    }

    fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) {}
        pool.shutdownNow()
    }

    /** Tries nodes in order; the first one that completes TLS and takes the token frame wins. */
    private fun openUpstream(): Socket? {
        val token = cfg.tokenProvider().toByteArray()
        for (node in selector.ordered()) {
            try {
                val s = PinnedTls.connect(node, cfg.connectTimeoutMs)
                val out = s.outputStream
                out.write(byteArrayOf((token.size shr 8).toByte(), token.size.toByte()))
                out.write(token)
                out.flush()
                return s
            } catch (_: Exception) {
                selector.recordFailure(node)
            }
        }
        return null
    }

    private fun relay(local: Socket) {
        local.tcpNoDelay = true
        val up = openUpstream()
        if (up == null) {
            local.close()
            return
        }
        val t = Thread { pipe(local.getInputStream(), up.getOutputStream(), local, up) }
        t.start()
        pipe(up.getInputStream(), local.getOutputStream(), local, up)
        t.join()
    }

    private fun pipe(i: InputStream, o: OutputStream, a: Socket, b: Socket) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                o.write(buf, 0, n)
                o.flush()
            }
        } catch (_: Exception) {
        } finally {
            try { a.close() } catch (_: Exception) {}
            try { b.close() } catch (_: Exception) {}
        }
    }
}
