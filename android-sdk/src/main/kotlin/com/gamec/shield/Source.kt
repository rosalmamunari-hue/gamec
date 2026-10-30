package com.gamec.shield

/** Where the current node list and a valid token come from. Hides which of the three modes is in use. */
internal interface Source {
    /** The nodes to use right now, or null if none are known. May refresh them (blocking). */
    fun nodes(): List<Node>?

    /** A token valid right now; [ordered] are the nodes to ask, best first, if the source must request one. */
    fun token(ordered: List<Node>): String?
}

internal class StaticSource(private val nodes: List<Node>, private val provider: () -> String) : Source {
    override fun nodes() = nodes
    override fun token(ordered: List<Node>): String? = provider()
}

internal class ControlSource(cfg: ControlConfig) : Source {
    private val sessions = SessionManager(cfg)
    override fun nodes() = sessions.get()?.nodes
    override fun token(ordered: List<Node>) = sessions.get()?.token
}

internal class DiscoverySource(
    private val directory: NodeDirectory,
    private val tokens: TokenManager,
) : Source {
    constructor(cfg: DiscoveryConfig) : this(
        NodeDirectory(cfg),
        TokenManager(cfg.deviceId, cfg.tokenMarginSec, cfg.timeoutMs),
    )

    override fun nodes() = directory.get()?.nodes
    override fun token(ordered: List<Node>) = tokens.get(ordered)
}

internal fun ShieldConfig.toSource(): Source = when {
    discovery != null -> DiscoverySource(discovery)
    control != null -> ControlSource(control)
    else -> StaticSource(nodes, tokenProvider!!)
}
