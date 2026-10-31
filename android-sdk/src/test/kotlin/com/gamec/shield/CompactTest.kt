package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket

/** The compact list format and the dw2. next names, against records made by the Go code. */
class CompactTest {
    // made by edge/shieldlist TestPrintCompactVectors; the nodes are 47.243.177.67:48860, 47.76.67.157:30522, [2001:db8::7]:23198
    private val goPub = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElsAZxR7AEl64NX4RaXbpaBab5U3jDxLp8WQIMjneko3g/uUmc9WWOu34ph8Aqd67GUh+tBHqVnsPn7acraHmpQ=="
    private val goSeal = "QiPWaFZWbmnziDuBA/lFxT3TsJmVZ6ySs5JLHZC22rE="
    private val goList = "05jl-6J5tBh3F9Dj2YcmpWgGecRoAHaIHtP0NzB1CBrWvfQoU_sKf-lwzg9bVf00rbPuOJtitZxAzW3eN6lGjAIBa0nSAMlF4QADBC_zsUO-3A5Imh61-v-EYCGlSzmyQSwEL0xDnXc6O16v-J3Ysb-CLyxboxN8TAYgAQ24AAAAAAAAAAAAAAAHWp5zrlK0J7Bu6Xak9NAW7Zm7"
    private val goSealed = "cppiHaCUbQIr3pONhbs6gxjYgoEHb8IUsscXJYySWGApk5cizF_nAOxZ4TmWRcwyzDI9LT63uutSQ3OiuzvF54uuEmV579lUPujR13U8ECTW1EjNyvIEAEvD2fy3Cf-xXiQfIDvyEg-5YyFCjrGMmG6p9v710wB0MFrE1TrRFVqUyHJBL4OIc5iWVY0W4jiQ8vPmaw99J8ArFtbLsOk61dV97M1l5gUFk-iruBEAeCQXZvq7R8oVgw"
    private val goNext = "JagTUudID-Esiz13lPFrgLCuBFJxn9PipQUPIloLqGoidDwUj2pJi6MS_m7xb167jlUG6-cos9XfuXmw_05_HgICa0nSAMlF4QACDWEuZXhhbXBsZS5jb20NYi5leGFtcGxlLm5ldA"
    private val goNodes = listOf(
        Node("47.243.177.67", 48860, "DkiaHrX6/4RgIaVLObJBLA=="),
        Node("47.76.67.157", 30522, "O16v+J3Ysb+CLyxboxN8TA=="),
        Node("2001:db8:0:0:0:0:0:7", 23198, "c65StCewbul2pPTQFu2Zuw=="),
    )

    @Test
    fun aCompactListMadeByTheGoCodeIsReadHere() {
        val l = ListVerifier.parse(listOf("v=spf1 -all", goList), goPub, 1_800_000_100)
        assertEquals(goNodes, l.nodes)
        assertEquals(1_800_000_000L, l.iat)
        assertEquals(listOf(goList), l.records)
    }

    @Test
    fun aSealedCompactListNeedsTheKey() {
        assertEquals(goNodes, ListVerifier.parse(listOf(goSealed), goPub, 1_800_000_100, goSeal).nodes)
        rejected { ListVerifier.parse(listOf(goSealed), goPub, 1_800_000_100) }
        assertEquals("an app with a key still reads a plain list", goNodes, ListVerifier.parse(listOf(goList), goPub, 1_800_000_100, goSeal).nodes)
    }

    @Test
    fun nextNamesMadeByTheGoCodeAreReadHere() {
        val n = NextVerifier.parse(listOf("other", goNext), goPub, 1_800_000_100, null)
        assertEquals(listOf("a.example.com", "b.example.net"), n.names)
        rejected { ListVerifier.parse(listOf(goNext), goPub, 1_800_000_100) } // a next record is no node list
        rejected { NextVerifier.parse(listOf(goList), goPub, 1_800_000_100, null) } // and the other way round
    }

    @Test
    fun aChangedOrForeignOrExpiredCompactListIsRejected() {
        val b = Base64.getUrlDecoder().decode(goList)
        b[b.size - 1] = (b[b.size - 1].toInt() xor 1).toByte()
        rejected { ListVerifier.parse(listOf(Base64.getUrlEncoder().withoutPadding().encodeToString(b)), goPub, 1_800_000_100) }
        rejected { ListVerifier.parse(listOf(goList), pub(newKey()), 1_800_000_100) }
        rejected { ListVerifier.parse(listOf(goList), goPub, 5_000_000_000) }
    }

    @Test
    fun theDirectoryReadsTheNextNamesFromDw2AndUsesThemFirst() {
        val k = newKey()
        val answers = ConcurrentHashMap<String, List<String>>()
        answers["_gs.example.com"] = listOf(compactList(k, 100))
        answers["dw2._gs.example.com"] = listOf(compactNext(k, 100, "alt.example.net", "_gs.example.com"))
        val saved = ArrayList<String>()
        val store = object : ListStore {
            override fun load() = emptyList<String>()
            override fun save(records: List<String>) { synchronized(saved) { saved.clear(); saved.addAll(records) } }
        }
        val d = NodeDirectory(DiscoveryConfig("_gs.example.com", pub(k), "device-1234567890abcdef", store = store),
            queryTxt = { answers[it] ?: emptyList() }, clock = { 200 })
        assertEquals(2, d.get()!!.nodes.size)
        val deadline = System.currentTimeMillis() + 5000
        while (d.namesForTest().first() != "alt.example.net" && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertEquals(listOf("alt.example.net", "_gs.example.com"), d.namesForTest())
        while (synchronized(saved) { saved.size } < 2 && System.currentTimeMillis() < deadline) Thread.sleep(10)
        // a restart remembers both: the list and where to look next
        val again = NodeDirectory(DiscoveryConfig("_gs.example.com", pub(k), "device-1234567890abcdef",
            store = object : ListStore {
                override fun load() = synchronized(saved) { saved.toList() }
                override fun save(records: List<String>) {}
            }), queryTxt = { emptyList() }, clock = { 200 })
        assertEquals("alt.example.net", again.namesForTest().first())
    }

    @Test
    fun aForgedDw2RecordIsIgnored() {
        val k = newKey()
        val answers = mapOf(
            "_gs.example.com" to listOf(compactList(k, 100)),
            "dw2._gs.example.com" to listOf(compactNext(newKey(), 100, "evil.example.net")),
        )
        val d = NodeDirectory(DiscoveryConfig("_gs.example.com", pub(k), "device-1234567890abcdef"),
            queryTxt = { answers[it] ?: emptyList() }, clock = { 200 })
        d.get()
        Thread.sleep(300)
        assertEquals(listOf("_gs.example.com"), d.namesForTest())
    }

    @Test
    fun aSixteenBytePinConnectsAndAWrongOneDoesNot() {
        val server = tlsServer()
        try {
            val full = "XQhBqnIseEBkYZBSf76E1egimSueG2ea2AimSmOqf9s="
            val short = Base64.getEncoder().encodeToString(Base64.getDecoder().decode(full).copyOf(16))
            PinnedTls.connect(Node("127.0.0.1", server.localPort, short), 3000).close()
            PinnedTls.connect(Node("127.0.0.1", server.localPort, full), 3000).close()
            val wrong = Base64.getDecoder().decode(short).also { it[15] = (it[15].toInt() xor 1).toByte() }
            rejected { PinnedTls.connect(Node("127.0.0.1", server.localPort, Base64.getEncoder().encodeToString(wrong)), 3000).close() }
            // a short prefix must never count as a match
            rejected { PinnedTls.connect(Node("127.0.0.1", server.localPort, Base64.getEncoder().encodeToString(Base64.getDecoder().decode(full).copyOf(8))), 3000).close() }
        } finally {
            server.close()
        }
    }

    // ---- helpers ----

    private fun newKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun pub(k: KeyPair) = Base64.getEncoder().encodeToString(k.public.encoded)

    private fun rejected(block: () -> Unit) {
        try {
            block()
        } catch (_: Exception) {
            return
        }
        fail("expected a rejection")
    }

    /** Signs a compact payload the way the Go code does (r||s over SHA-256(domain || payload)). */
    private fun sign(k: KeyPair, payload: ByteArray): String {
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(k.private)
            update("gamec compact list v2\u0000".toByteArray(Charsets.ISO_8859_1))
            update(payload)
            sign()
        }
        // DER SEQUENCE { INTEGER r, INTEGER s } -> r||s, 32 bytes each
        var i = 2
        fun int(): ByteArray {
            val len = der[i + 1].toInt()
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len)).toByteArray().takeLast(32).toByteArray()
            i += 2 + len
            return ByteArray(32 - v.size) + v
        }
        val raw = int() + int()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw + payload)
    }

    private fun header(kind: Int, iat: Long, count: Int) = ByteBuffer.allocate(11).put(2).put(kind.toByte())
        .putInt(iat.toInt()).putInt(10_000).put(count.toByte()).array()

    private fun compactList(k: KeyPair, iat: Long): String {
        val node = { last: Int -> byteArrayOf(4, 10, 0, 0, last.toByte(), 0x78, 0x50) + ByteArray(16) { 7 } }
        return sign(k, header(1, iat, 2) + node(1) + node(2))
    }

    private fun compactNext(k: KeyPair, iat: Long, vararg names: String): String {
        var p = header(2, iat, names.size)
        for (n in names) p += byteArrayOf(n.length.toByte()) + n.toByteArray()
        return sign(k, p)
    }

    private fun tlsServer(): SSLServerSocket {
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVtSnEiq0SKOQwhf8tKi/XR/3x7xl0tNsidOvQJ5BsBahRANCAASkrywLfFLjlOgpjE+9GpHGLALgh6+yknBz0v+8eGfrYc5tbEkQwvo3Aai+Lc9jG4vv9RWcPAb2XHtvbRQYpSW3")))
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode("MIIBdTCCARugAwIBAgIUP+v4a4wi1Q+8e7wu4Dpbw8dPS54wCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEdGVzdDAgFw0yNjEwMzEwMzIzNDVaGA8yMTI2MTAwNzAzMjM0NVowDzENMAsGA1UEAwwEdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKSvLAt8UuOU6CmMT70akcYsAuCHr7KScHPS/7x4Z+thzm1sSRDC+jcBqL4tz2Mbi+/1FZw8BvZce29tFBilJbejUzBRMB0GA1UdDgQWBBQOSLBhtncMr6mTXnMXQJGxe7Qo3zAfBgNVHSMEGDAWgBQOSLBhtncMr6mTXnMXQJGxe7Qo3zAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDxdKVQS0sHy2mOgQNAWxUh7R8OCeHH/juVuiaqEQY5kgIgOWw017iiUzlOCNHMS1/Exc3tCDUd5EX9f38MOnYqKTY=")))
        val ks = KeyStore.getInstance("PKCS12").apply { load(null, null); setKeyEntry("k", key, CharArray(0), arrayOf(cert)) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, CharArray(0)) }
        val ctx = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
        val s = ctx.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        Thread {
            while (!s.isClosed) {
                try {
                    val c = s.accept()
                    Thread { try { c.getInputStream().read() } catch (_: Exception) {} finally { c.close() } }.start()
                } catch (_: Exception) {
                }
            }
        }.also { it.isDaemon = true; it.start() }
        return s
    }
}
