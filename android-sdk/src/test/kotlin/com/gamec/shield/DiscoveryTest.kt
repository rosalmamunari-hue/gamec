package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Pure JVM tests for the DNS discovery path; no network, no edge node. */
class DiscoveryTest {
    private fun newKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun pub(k: KeyPair) = Base64.getEncoder().encodeToString(k.public.encoded)

    private fun nodes(n: Int) = (1..n).map { Node("10.0.0.$it", 30800, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg=") }

    /** Same format as edge/cmd/signlist. */
    private fun records(key: KeyPair, nodes: List<Node>, iat: Long = 100, exp: Long = 10_000, chunk: Int = 200): List<String> {
        val nodesJson = nodes.joinToString(",") { "{\"h\":\"${it.host}\",\"p\":${it.port},\"k\":\"${it.pinSha256}\"}" }
        val payload = "{\"v\":1,\"iat\":$iat,\"exp\":$exp,\"nodes\":[$nodesJson]}".toByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(payload)
            sign()
        }
        val enc = Base64.getUrlEncoder().withoutPadding()
        val chunks = (enc.encodeToString(payload) + "." + enc.encodeToString(sig)).chunked(chunk)
        if (chunks.size == 1) return chunks // a list that fits is one bare record, like the edge tools make
        return chunks.mapIndexed { i, c -> "${i + 1}/${chunks.size}:$c" }
    }

    private fun cfg(key: KeyPair, store: ListStore? = null, refreshSec: Long = 600, retrySec: Long = 30) =
        DiscoveryConfig("_gs.example.com", pub(key), "device-1234567890abcdef",
            refreshSec = refreshSec, retrySec = retrySec, store = store)

    private fun assertRejected(block: () -> Unit) {
        try {
            block()
            fail("expected the node list to be rejected")
        } catch (_: Exception) {
        }
    }

    // ---- DoH parsing ----

    @Test
    fun dohJoinsSplitQuotedStrings() {
        val json = """{"Status":0,"Answer":[{"name":"x","type":16,"TTL":60,"data":"\"1/1:a\" \"bcdef\""}]}"""
        assertEquals(listOf("1/1:abcdef"), Doh.parse(json))
    }

    @Test
    fun dohIgnoresOtherRecordTypesAndFailures() {
        assertEquals(emptyList<String>(), Doh.parse("""{"Status":3}"""))
        assertEquals(emptyList<String>(), Doh.parse("""{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"""))
    }

    @Test
    fun dohFallsThroughToTheNextProvider() {
        val urls = ArrayList<String>()
        val out = Doh.queryTxt("_gs.example.com", listOf("http://bad/dns", "http://good/dns"), 1000) { url, _ ->
            urls += url
            if (url.startsWith("http://bad")) throw java.io.IOException("unreachable")
            """{"Status":0,"Answer":[{"type":16,"data":"\"1/1:zz\""}]}"""
        }
        assertEquals(listOf("1/1:zz"), out)
        assertEquals(2, urls.size)
        assertTrue(urls[1].contains("name=_gs.example.com") && urls[1].contains("type=TXT"))
    }

    @Test
    fun dohReturnsNothingWhenEveryProviderFails() {
        val out = Doh.queryTxt("x", listOf("http://a", "http://b"), 1000) { _, _ -> throw java.io.IOException("down") }
        assertTrue(out.isEmpty())
    }

    // ---- signed list ----

    @Test
    fun aShortListIsOneBareRecordAndParses() {
        val k = newKey()
        val recs = records(k, nodes(3), chunk = 100_000)
        assertEquals(1, recs.size)
        assertTrue(!recs[0].contains(":") && ListVerifier.isRecord(recs[0]))
        assertEquals(nodes(3), ListVerifier.parse(recs, pub(k), 200).nodes)
        // a TXT record that merely sits next to it is ignored
        assertEquals(nodes(3), ListVerifier.parse(recs + "v=spf1 -all", pub(k), 200).nodes)
    }

    @Test
    fun validMultiChunkListParses() {
        val k = newKey()
        val recs = records(k, nodes(5))
        assertTrue("5 nodes should need several records", recs.size > 1)
        val l = ListVerifier.parse(recs, pub(k), 200)
        assertEquals(nodes(5), l.nodes)
        assertEquals(100L, l.iat)
    }

    @Test
    fun recordOrderDoesNotMatter() {
        val k = newKey()
        val l = ListVerifier.parse(records(k, nodes(5)).reversed(), pub(k), 200)
        assertEquals(5, l.nodes.size)
    }

    @Test
    fun tamperedListIsRejected() {
        val k = newKey()
        val recs = records(k, nodes(2)).toMutableList()
        val s = recs[0]
        val i = s.length - 10
        recs[0] = s.substring(0, i) + (if (s[i] == 'A') 'B' else 'A') + s.substring(i + 1)
        assertRejected { ListVerifier.parse(recs, pub(k), 200) }
    }

    @Test
    fun listSignedByAnotherKeyIsRejected() {
        assertRejected { ListVerifier.parse(records(newKey(), nodes(2)), pub(newKey()), 200) }
    }

    @Test
    fun expiredListIsRejected() {
        val k = newKey()
        assertRejected { ListVerifier.parse(records(k, nodes(2), exp = 150), pub(k), 200) }
    }

    @Test
    fun incompleteSetIsRejected() {
        val k = newKey()
        assertRejected { ListVerifier.parse(records(k, nodes(5)).drop(1), pub(k), 200) }
    }

    @Test
    fun unrelatedTxtRecordsAreIgnored() {
        val k = newKey()
        val recs = records(k, nodes(2)) + listOf("v=spf1 -all", "google-site-verification=abc")
        assertEquals(2, ListVerifier.parse(recs, pub(k), 200).nodes.size)
    }

    @Test
    fun mixedVersionsDuringPropagationPickTheCompleteValidOne() {
        val k = newKey()
        val old = records(k, nodes(5), iat = 100) // several chunks
        val fresh = records(k, nodes(1), iat = 200) // a single chunk
        val l = ListVerifier.parse(old.drop(1) + fresh, pub(k), 300) // old set is incomplete
        assertEquals(1, l.nodes.size)
        assertEquals(200L, l.iat)
    }

    // ---- directory: caching, rollback, stale use ----

    @Test
    fun directoryCachesUntilTheRefreshInterval() {
        val k = newKey()
        var now = 1000L
        var queries = 0
        val d = NodeDirectory(cfg(k, refreshSec = 600), { queries++; records(k, nodes(2), iat = 900, exp = 99_999) }, { now })
        val first = d.get()
        assertNotNull(first)
        assertSame(first, d.get())
        assertEquals(1, queries)
        now = 1599
        d.get()
        assertEquals(1, queries)
        now = 1601
        d.get()
        assertEquals(2, queries)
    }

    @Test
    fun directoryNeverGoesBackToAnOlderList() {
        val k = newKey()
        var now = 1000L
        var iat = 900L
        val d = NodeDirectory(cfg(k, refreshSec = 10), { records(k, nodes(iat.toInt() / 450), iat = iat, exp = 99_999) }, { now })
        val newer = d.get()!!
        assertEquals(2, newer.nodes.size)
        iat = 450 // an attacker replays an older signed list
        now = 1100
        val after = d.get()!!
        assertEquals("replayed older list must be ignored", 900L, after.iat)
    }

    @Test
    fun directoryKeepsUsingTheLastListWhileDnsIsDownThenGivesUp() {
        val k = newKey()
        var now = 1000L
        var down = false
        val d = NodeDirectory(cfg(k, refreshSec = 10, retrySec = 10),
            { if (down) emptyList() else records(k, nodes(2), iat = 900, exp = 2000) }, { now })
        assertNotNull(d.get())
        down = true
        now = 1500
        assertNotNull("stale but unexpired list is still usable", d.get())
        now = 2001
        assertNull("an expired list must not be used", d.get())
    }

    @Test
    fun directoryDoesNotHammerDnsAfterAFailure() {
        val k = newKey()
        var now = 1000L
        var queries = 0
        val d = NodeDirectory(cfg(k, retrySec = 30), { queries++; emptyList() }, { now })
        repeat(5) { d.get() }
        assertEquals(1, queries)
        now = 1031
        d.get()
        assertEquals(2, queries)
    }

    @Test
    fun directoryStartsFromTheSavedListWhenDnsIsUnreachable() {
        val k = newKey()
        val saved = records(k, nodes(2), iat = 900, exp = 99_999)
        val store = object : ListStore {
            override fun load() = saved
            override fun save(records: List<String>) {}
        }
        val d = NodeDirectory(cfg(k, store = store), { emptyList() }, { 1000L })
        assertEquals(2, d.get()!!.nodes.size)
    }

    @Test
    fun directorySavesEachGoodListToTheStore() {
        val k = newKey()
        var saved: List<String> = emptyList()
        val store = object : ListStore {
            override fun load() = emptyList<String>()
            override fun save(records: List<String>) { saved = records }
        }
        NodeDirectory(cfg(k, store = store), { records(k, nodes(2), exp = 99_999) }, { 1000L }).get()
        assertTrue(saved.isNotEmpty() && saved.all { ListVerifier.isRecord(it) })
    }

    // ---- token manager ----

    @Test
    fun tokenIsCachedUntilNearExpiry() {
        var now = 100L
        var asked = 0
        val m = TokenManager("device-1234567890abcdef", 60, 1000, { _, _, _ -> asked++; IssuedToken("t$asked", 400) }, { now })
        assertEquals("t1", m.get(nodes(1)))
        assertEquals("t1", m.get(nodes(1)))
        now = 339
        assertEquals("t1", m.get(nodes(1)))
        now = 341
        assertEquals("t2", m.get(nodes(1)))
    }

    @Test
    fun tokenRequestTriesTheNextNodeOnFailure() {
        val tried = ArrayList<String>()
        val m = TokenManager("device-1234567890abcdef", 60, 1000, { n, _, _ ->
            tried += n.host
            if (n.host == "10.0.0.1") throw java.io.IOException("down") else IssuedToken("ok", 400)
        }, { 100L })
        assertEquals("ok", m.get(nodes(2)))
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), tried)
    }

    @Test
    fun staleTokenIsUsedWhileEveryNodeRefusesThenNothing() {
        var now = 100L
        var down = false
        val m = TokenManager("device-1234567890abcdef", 60, 1000, { _, _, _ ->
            if (down) throw java.io.IOException("down") else IssuedToken("t", 400)
        }, { now })
        m.get(nodes(1))
        down = true
        now = 350
        assertEquals("t", m.get(nodes(1)))
        now = 401
        assertNull(m.get(nodes(1)))
    }
}
