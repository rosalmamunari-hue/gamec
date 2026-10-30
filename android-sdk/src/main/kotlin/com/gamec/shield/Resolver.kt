package com.gamec.shield

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** One way of asking DNS for TXT records. */
internal fun interface TxtResolver {
    fun query(name: String, timeoutMs: Int): List<String>
}

internal class DohResolver(private val url: String) : TxtResolver {
    override fun query(name: String, timeoutMs: Int) = Doh.queryTxt(name, listOf(url), timeoutMs)
}

internal class DotResolver(private val host: String, private val port: Int = 853) : TxtResolver {
    override fun query(name: String, timeoutMs: Int) = Dot.query(host, port, name, timeoutMs)
}

internal class Do53Resolver(private val host: String, private val port: Int = 53) : TxtResolver {
    override fun query(name: String, timeoutMs: Int) = Do53.query(host, port, name = name, timeoutMs = timeoutMs)
}

internal object DnsDefaults {
    /** JSON DoH endpoints reached by IP address, so no prior (possibly poisoned) DNS lookup is needed. */
    val doh = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve", "https://223.5.5.5/resolve")

    /** DNS-over-TLS servers on port 853, by IP address. */
    val dot = listOf("8.8.8.8", "1.1.1.1", "223.5.5.5")

    /** Plain DNS servers on port 53, by IP address. */
    val do53 = listOf("8.8.8.8", "1.1.1.1", "223.5.5.5")
}

internal object Race {
    private val NONE = Any()

    /**
     * Starts [tasks] [staggerMs] apart (task i begins after i * staggerMs) and returns the first non-null result.
     * Returns null if every task comes back empty or [timeoutMs] passes. Losers are interrupted; they end on
     * their own socket timeouts and never throw out of their thread.
     */
    @Suppress("UNCHECKED_CAST")
    fun <T : Any> first(tasks: List<() -> T?>, staggerMs: Long, timeoutMs: Long): T? {
        if (tasks.isEmpty()) return null
        val results = LinkedBlockingQueue<Any>()
        val threads = tasks.mapIndexed { i, task ->
            Thread {
                try {
                    if (i > 0) Thread.sleep(i * staggerMs)
                    results.put(task() ?: NONE)
                } catch (_: Throwable) {
                    results.offer(NONE)
                }
            }.also { it.isDaemon = true; it.start() }
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        try {
            var pending = tasks.size
            while (pending > 0) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) break
                val r = results.poll(left, TimeUnit.MILLISECONDS) ?: break
                pending--
                if (r !== NONE) return r as T
            }
            return null
        } finally {
            threads.forEach { it.interrupt() }
        }
    }
}

internal object Resolvers {
    /** Name of the resolver that answered last, for diagnostics. */
    @Volatile var lastWinner: String = ""

    /** DoT, DoH and plain DNS (port 53) interleaved so all three transports start early. */
    fun build(cfg: DiscoveryConfig): List<Pair<String, TxtResolver>> {
        fun hostPort(s: String, defaultPort: Int) =
            if (':' in s) s.substringBefore(':') to s.substringAfter(':').toInt() else s to defaultPort
        val dot = cfg.dotServers.map { s ->
            val (h, p) = hostPort(s, 853)
            "dot:$s" to DotResolver(h, p) as TxtResolver
        }
        val doh = cfg.dohProviders.map { "doh:$it" to DohResolver(it) as TxtResolver }
        val do53 = cfg.do53Servers.map { s ->
            val (h, p) = hostPort(s, 53)
            "do53:$s" to Do53Resolver(h, p) as TxtResolver
        }
        val out = ArrayList<Pair<String, TxtResolver>>()
        for (i in 0 until maxOf(dot.size, doh.size, do53.size)) {
            dot.getOrNull(i)?.let { out += it }
            doh.getOrNull(i)?.let { out += it }
            do53.getOrNull(i)?.let { out += it }
        }
        return out
    }

    /**
     * Asks every resolver, staggered, and returns the records of the first one whose answer passes [valid]
     * (for the node list: a correct signature). A resolver that answers with garbage or a forged list loses.
     */
    fun race(
        resolvers: List<Pair<String, TxtResolver>>,
        name: String,
        timeoutMs: Int,
        staggerMs: Long,
        valid: (List<String>) -> Boolean,
    ): List<String> {
        val tasks = resolvers.map { (label, r) ->
            {
                val recs = r.query(name, timeoutMs)
                if (recs.isNotEmpty() && valid(recs)) { lastWinner = label; recs } else null
            }
        }
        val overall = timeoutMs + staggerMs * (tasks.size - 1).coerceAtLeast(0)
        return Race.first(tasks, staggerMs, overall) ?: emptyList()
    }

    fun query(cfg: DiscoveryConfig, name: String): List<String> =
        race(build(cfg), name, cfg.timeoutMs, cfg.resolverStaggerMs) { recs ->
            try {
                ListVerifier.parse(recs, cfg.publicKey, System.currentTimeMillis() / 1000)
                true
            } catch (_: Exception) {
                false
            }
        }
}
