package com.gamec.shield

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
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
    private val sessions = cfg.control?.let { SessionManager(it) }
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
                    sessions?.get()?.let { selector.update(it.nodes) }
                    selector.probeAll(cfg.connectTimeoutMs)
                    var waited = 0L
                    while (running.get() && waited < cfg.reprobeIntervalMs) {
                        Thread.sleep(500)
                        waited += 500
                    }
                }
            } catch (_: Exception) {
                // InterruptedException from stop(), or a failure fetching the session; the loop just ends
            }
        }
        pool.execute {
            while (running.get()) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                try {
                    pool.execute { relay(c) }
                } catch (_: RejectedExecutionException) {
                    // stop() raced with this connection
                    try { c.close() } catch (_: Exception) {}
                    break
                }
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
        val tokenStr = if (sessions != null) {
            val s = sessions.get() ?: return null
            selector.update(s.nodes)
            s.token
        } else {
            cfg.tokenProvider!!()
        }
        val token = tokenStr.toByteArray()
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

    /**
     * Runs on a pool thread. stop() interrupts these threads, and an exception that escapes here would be
     * uncaught, which kills the whole app on Android, so nothing may propagate.
     */
    private fun relay(local: Socket) {
        var up: Socket? = null
        try {
            local.tcpNoDelay = true
            up = openUpstream()
            if (up == null) {
                local.close()
                return
            }
            val upstream = up
            val t = Thread { pipe(local.getInputStream(), upstream.getOutputStream(), local, upstream) }
            t.start()
            pipe(upstream.getInputStream(), local.getOutputStream(), local, upstream)
            t.join()
        } catch (_: Exception) {
            // includes InterruptedException from stop(); just release both sockets
            try { local.close() } catch (_: Exception) {}
            try { up?.close() } catch (_: Exception) {}
        }
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
