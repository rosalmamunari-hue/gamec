package com.gamec.shield

import java.util.concurrent.ConcurrentHashMap

/** Tracks measured latency per node and temporarily benches nodes that fail. The node set can change at runtime. */
internal class NodeSelector(initial: List<Node>, private val cooldownMs: Long) {
    @Volatile private var nodes: List<Node> = initial
    private val rtt = ConcurrentHashMap<Node, Long>()
    private val benchedUntil = ConcurrentHashMap<Node, Long>()

    fun update(newNodes: List<Node>) {
        if (newNodes == nodes) return
        nodes = newNodes
        rtt.keys.retainAll(newNodes.toSet())
        benchedUntil.keys.retainAll(newNodes.toSet())
    }

    fun recordRtt(n: Node, ms: Long) {
        rtt[n] = ms
        benchedUntil.remove(n)
    }

    fun recordFailure(n: Node) {
        benchedUntil[n] = System.currentTimeMillis() + cooldownMs
        rtt.remove(n)
    }

    /** Healthy nodes fastest first (unmeasured after measured); benched nodes last, as a final resort. */
    fun ordered(): List<Node> {
        val now = System.currentTimeMillis()
        val (benched, ok) = nodes.partition { (benchedUntil[it] ?: 0L) > now }
        return ok.sortedBy { rtt[it] ?: Long.MAX_VALUE } + benched
    }

    /** Measure TLS handshake time to every node in parallel. */
    fun probeAll(timeoutMs: Int) {
        nodes.map { n ->
            Thread {
                val t0 = System.nanoTime()
                try {
                    PinnedTls.connect(n, timeoutMs).close()
                    recordRtt(n, (System.nanoTime() - t0) / 1_000_000)
                } catch (_: Exception) {
                    recordFailure(n)
                }
            }.also { it.start() }
        }.forEach { it.join() }
    }
}
