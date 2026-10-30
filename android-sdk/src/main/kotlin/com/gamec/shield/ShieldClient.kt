package com.gamec.shield

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicBoolean

/** Opens one upstream connection to [node] and authenticates it with [token]. */
internal fun interface Connector {
    fun connect(node: Node, token: ByteArray, timeoutMs: Int): Socket
}

/** Pinned TLS 1.3, then the token frame (2-byte length + token). */
internal object TlsConnector : Connector {
    override fun connect(node: Node, token: ByteArray, timeoutMs: Int): Socket {
        val s = PinnedTls.connect(node, timeoutMs)
        try {
            val out = s.outputStream
            out.write(byteArrayOf((token.size shr 8).toByte(), token.size.toByte()))
            out.write(token)
            out.flush()
            return s
        } catch (e: Exception) {
            try { s.close() } catch (_: Exception) {}
            throw e
        }
    }
}

/**
 * Local TCP proxy. The game connects to 127.0.0.1:[ShieldClient.start] result; each connection is relayed
 * over pinned TLS 1.3 to the fastest healthy edge node, which forwards to the hidden origin.
 *
 *   val shield = ShieldClient(ShieldConfig(nodes, { fetchTokenFromLoginServer() }))
 *   val port = shield.start()
 *   // point the game socket at 127.0.0.1:port
 *
 * Reconnecting: if no node can be reached the SDK keeps retrying for [ShieldConfig.connectRetryWindowMs]
 * with the game's socket held open. A connection that was established and then dies is closed, which makes
 * the game reconnect; that reconnect picks a healthy node. A connection cannot be moved to another node
 * while it lives, because the node-to-origin leg dies with the node.
 */
class ShieldClient internal constructor(
    private val cfg: ShieldConfig,
    private val source: Source,
    private val connector: Connector,
) {
    constructor(cfg: ShieldConfig) : this(cfg, cfg.toSource(), TlsConnector)

    private class Conn(val local: Socket, val upstream: Socket) {
        /** Millis when data was first sent upstream with nothing received since; 0 = nothing outstanding. */
        @Volatile var pendingSince = 0L
    }

    private val selector = NodeSelector(cfg.nodes, cfg.failCooldownMs)
    private val pool = Executors.newCachedThreadPool()
    private val running = AtomicBoolean(false)
    private val live = ConcurrentHashMap.newKeySet<Conn>()
    private var server: ServerSocket? = null

    private fun emit(block: ShieldListener.() -> Unit) {
        try { cfg.listener?.block() } catch (_: Throwable) {}
    }

    fun start(): Int {
        check(running.compareAndSet(false, true)) { "already started" }
        val ss = ServerSocket(cfg.localPort, 50, InetAddress.getByName("127.0.0.1"))
        server = ss
        pool.execute {
            try {
                while (running.get()) {
                    source.nodes()?.let { selector.update(it) }
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
            try {
                while (running.get()) {
                    Thread.sleep(500)
                    watchdog()
                }
            } catch (_: Exception) {
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
        for (c in live) closeBoth(c.local, c.upstream)
    }

    /** Closes connections that were sent data but heard nothing back for too long. */
    private fun watchdog() {
        val limit = cfg.deadAfterUnansweredMs
        if (limit <= 0) return
        val now = System.currentTimeMillis()
        for (c in live) {
            val since = c.pendingSince
            if (since != 0L && now - since > limit) {
                live.remove(c)
                emit { onConnectionLost("no response for ${(now - since) / 1000}s") }
                closeBoth(c.local, c.upstream)
            }
        }
    }

    /** One round: current nodes, a token, then each node in order. */
    private fun tryOnce(): Socket? {
        val nodes = source.nodes() ?: run { source.refreshNow(); source.nodes() } ?: return null
        selector.update(nodes)
        // In discovery mode tokens come from the nodes, so a failed token means the nodes failed too
        val token = (source.token(selector.ordered()) ?: run { source.refreshNow(); return null }).toByteArray()
        for (node in selector.ordered()) {
            try {
                val s = connector.connect(node, token, cfg.connectTimeoutMs)
                emit { onConnected(node.toString()) }
                return s
            } catch (_: Exception) {
                selector.recordFailure(node)
            }
        }
        source.refreshNow() // every node failed: the next round may already have a newer list
        return null
    }

    /**
     * Rounds of [tryOnce] with exponential backoff and jitter until one works or the retry window ends.
     * Nodes and token are looked up again every round, so a refreshed node list is picked up.
     */
    private fun openUpstream(): Socket? {
        val start = System.currentTimeMillis()
        var backoff = cfg.retryMinMs
        var attempt = 0
        while (running.get()) {
            tryOnce()?.let { return it }
            val left = cfg.connectRetryWindowMs - (System.currentTimeMillis() - start)
            if (left <= 0) break
            attempt++
            emit { onRetrying(attempt) }
            val jitter = ThreadLocalRandom.current().nextLong(backoff / 2 + 1)
            Thread.sleep(minOf(backoff + jitter, left))
            backoff = minOf(backoff * 2, cfg.retryMaxMs)
        }
        if (running.get()) emit { onConnectFailed() }
        return null
    }

    private fun closeBoth(a: Socket, b: Socket) {
        try { a.close() } catch (_: Exception) {}
        try { b.close() } catch (_: Exception) {}
    }

    /**
     * Runs on a pool thread. stop() interrupts these threads, and an exception that escapes here would be
     * uncaught, which kills the whole app on Android, so nothing may propagate.
     */
    private fun relay(local: Socket) {
        var conn: Conn? = null
        var up: Socket? = null
        try {
            local.tcpNoDelay = true
            up = openUpstream()
            if (up == null) {
                local.close()
                return
            }
            val upstream = up
            val c = Conn(local, upstream)
            conn = c
            live.add(c)
            val t = Thread { pipe(local.getInputStream(), upstream.getOutputStream(), c, outbound = true) }
            t.start()
            pipe(upstream.getInputStream(), local.getOutputStream(), c, outbound = false)
            t.join()
        } catch (_: Exception) {
            // includes InterruptedException from stop(); just release both sockets
            try { local.close() } catch (_: Exception) {}
            try { up?.close() } catch (_: Exception) {}
        } finally {
            conn?.let { live.remove(it) }
        }
    }

    private fun pipe(i: InputStream, o: OutputStream, c: Conn, outbound: Boolean) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                if (!outbound) c.pendingSince = 0L
                o.write(buf, 0, n)
                o.flush()
                if (outbound && c.pendingSince == 0L) c.pendingSince = System.currentTimeMillis()
            }
        } catch (_: Exception) {
        } finally {
            closeBoth(c.local, c.upstream)
        }
    }
}
