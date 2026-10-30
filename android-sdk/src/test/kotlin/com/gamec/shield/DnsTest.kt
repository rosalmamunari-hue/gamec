package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** DNS wire format, DoT framing and the resolver race; no external network. */
class DnsTest {
    // ---- helpers: build DNS responses the way real servers do ----

    private fun u16(o: ByteArrayOutputStream, v: Int) { o.write(v shr 8); o.write(v and 0xFF) }

    private fun nameBytes(name: String): ByteArray {
        val o = ByteArrayOutputStream()
        for (l in name.split('.')) { o.write(l.length); o.write(l.toByteArray()) }
        o.write(0)
        return o.toByteArray()
    }

    /** A response to a TXT question; each answer is a list of TXT strings (one record). Answers use a name pointer. */
    private fun response(id: Int, name: String, answers: List<List<String>>, rcode: Int = 0, qr: Boolean = true,
                         truncated: Boolean = false): ByteArray {
        val o = ByteArrayOutputStream()
        u16(o, id)
        u16(o, (if (qr) 0x8180 else 0x0100) or rcode or (if (truncated) 0x0200 else 0))
        u16(o, 1); u16(o, answers.size); u16(o, 0); u16(o, 0)
        o.write(nameBytes(name)); u16(o, 16); u16(o, 1)
        for (strings in answers) {
            o.write(0xC0); o.write(12) // pointer to the question name at offset 12
            u16(o, 16); u16(o, 1)
            o.write(0); o.write(0); o.write(0); o.write(60) // TTL
            val rd = ByteArrayOutputStream()
            for (s in strings) { rd.write(s.length); rd.write(s.toByteArray()) }
            u16(o, rd.size()); o.write(rd.toByteArray())
        }
        return o.toByteArray()
    }

    // ---- wire format ----

    @Test
    fun queryHasTheExpectedShape() {
        val q = DnsWire.buildQuery("_gs.example.com", 0x1234)
        assertEquals(0x12, q[0].toInt()); assertEquals(0x34, q[1].toInt())
        assertEquals(0x01, q[2].toInt()); assertEquals(0x00, q[3].toInt()) // RD
        assertEquals(1, q[5].toInt()) // one question
        assertEquals(3, q[12].toInt()) // first label "_gs"
        assertEquals("_gs", String(q, 13, 3))
        assertEquals(16, q[q.size - 3].toInt()) // type TXT
        assertEquals(1, q[q.size - 1].toInt()) // class IN
    }

    @Test
    fun overlongLabelIsRejected() {
        try {
            DnsWire.buildQuery("a".repeat(64) + ".com", 1)
            fail("labels over 63 bytes are illegal")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun parsesSeveralRecordsAndJoinsTheStringsOfEachOne() {
        val msg = response(7, "_gs.example.com", listOf(listOf("1/2:", "abc"), listOf("2/2:def")))
        assertEquals(listOf("1/2:abc", "2/2:def"), DnsWire.parseTxt(msg, 7))
    }

    @Test
    fun noSuchNameGivesAnEmptyList() {
        assertEquals(emptyList<String>(), DnsWire.parseTxt(response(9, "x.example", emptyList(), rcode = 3), 9))
    }

    @Test
    fun serverFailureIsAnError() {
        try {
            DnsWire.parseTxt(response(9, "x.example", emptyList(), rcode = 2), 9)
            fail("SERVFAIL must not look like an empty answer")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun answerForAnotherQuestionIsRejected() {
        try {
            DnsWire.parseTxt(response(1, "x.example", listOf(listOf("v"))), 2)
            fail("a response with the wrong id must be refused")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun aQueryIsNotAResponse() {
        try {
            DnsWire.parseTxt(response(1, "x.example", listOf(listOf("v")), qr = false), 1)
            fail("QR bit not set")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun truncatedMessagesNeverReadOutOfBounds() {
        val full = response(3, "_gs.example.com", listOf(listOf("hello world")))
        for (cut in 0 until full.size) {
            try {
                DnsWire.parseTxt(full.copyOf(cut), 3)
                if (cut < full.size - 1) fail("cut at $cut should not parse as a complete answer") // last byte is rdata
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    // ---- DoT framing over a plain loopback socket (TLS itself is covered on a device) ----

    private fun dnsTcpServer(respond: (query: ByteArray) -> ByteArray?): ServerSocket {
        val ss = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        Thread {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                Thread {
                    try {
                        val inp = DataInputStream(c.getInputStream())
                        val q = ByteArray(inp.readUnsignedShort()); inp.readFully(q)
                        val r = respond(q)
                        if (r != null) {
                            c.getOutputStream().write(byteArrayOf((r.size shr 8).toByte(), r.size.toByte()))
                            c.getOutputStream().write(r)
                        }
                        c.close()
                    } catch (_: Exception) {
                    }
                }.also { it.isDaemon = true }.start()
            }
        }.also { it.isDaemon = true }.start()
        return ss
    }

    private fun plain(ss: ServerSocket) = { _: String, _: Int, _: Int -> Socket("127.0.0.1", ss.localPort) }

    @Test
    fun dotRoundTrip() {
        val ss = dnsTcpServer { q ->
            val id = ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF)
            response(id, "_gs.example.com", listOf(listOf("1/1:payload")))
        }
        try {
            assertEquals(listOf("1/1:payload"), Dot.query("127.0.0.1", 853, "_gs.example.com", 2000, plain(ss)))
        } finally { ss.close() }
    }

    @Test
    fun dotServerThatHangsUpIsAnError() {
        val ss = dnsTcpServer { null }
        try {
            Dot.query("127.0.0.1", 853, "_gs.example.com", 1000, plain(ss))
            fail("closing without an answer must be an error, not an empty result")
        } catch (_: Exception) {
        } finally { ss.close() }
    }

    @Test
    fun dotServerAnsweringTheWrongQuestionIsRefused() {
        val ss = dnsTcpServer { response(0x7777, "_gs.example.com", listOf(listOf("forged"))) }
        try {
            Dot.query("127.0.0.1", 853, "_gs.example.com", 1000, plain(ss))
            fail("id mismatch")
        } catch (_: Exception) {
        } finally { ss.close() }
    }

    // ---- the race ----

    @Test
    fun theFirstUsableAnswerWinsEvenIfEarlierResolversAreSlowOrBroken() {
        val order = CopyOnWriteArrayList<String>()
        val resolvers = listOf(
            "dot:blocked" to TxtResolver { _, _ -> order += "dot"; Thread.sleep(3000); emptyList() },
            "doh:broken" to TxtResolver { _, _ -> order += "doh"; throw java.io.IOException("unreachable") },
            "doh:good" to TxtResolver { _, _ -> order += "good"; listOf("1/1:ok") },
        )
        val t0 = System.currentTimeMillis()
        val got = Resolvers.race(resolvers, "n", 5000, 50) { it.isNotEmpty() }
        val took = System.currentTimeMillis() - t0
        assertEquals(listOf("1/1:ok"), got)
        assertTrue("should not wait for the slow resolver, took ${took}ms", took < 1500)
        assertEquals("doh:good", Resolvers.lastWinner)
    }

    @Test
    fun aResolverWithAForgedAnswerDoesNotWin() {
        val resolvers = listOf(
            "dot:evil" to TxtResolver { _, _ -> listOf("forged") },
            "doh:honest" to TxtResolver { _, _ -> Thread.sleep(300); listOf("genuine") },
        )
        val got = Resolvers.race(resolvers, "n", 3000, 20) { it == listOf("genuine") }
        assertEquals(listOf("genuine"), got)
    }

    @Test
    fun laterResolversAreNotStartedOnceTheFirstHasWon() {
        val started = AtomicInteger()
        val resolvers = listOf(
            "a" to TxtResolver { _, _ -> started.incrementAndGet(); listOf("x") },
            "b" to TxtResolver { _, _ -> started.incrementAndGet(); listOf("x") },
            "c" to TxtResolver { _, _ -> started.incrementAndGet(); listOf("x") },
        )
        Resolvers.race(resolvers, "n", 3000, 400) { true }
        Thread.sleep(1000)
        assertEquals("the stagger exists so a fast first answer avoids the extra queries", 1, started.get())
    }

    @Test
    fun nothingUsableMeansEmptyAndNoCrash() {
        val uncaught = CopyOnWriteArrayList<Throwable>()
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught += e }
        try {
            val resolvers = listOf(
                "a" to TxtResolver { _, _ -> throw IllegalStateException("boom") },
                "b" to TxtResolver { _, _ -> emptyList() },
            )
            assertEquals(emptyList<String>(), Resolvers.race(resolvers, "n", 1000, 10) { true })
            Thread.sleep(300)
        } finally { Thread.setDefaultUncaughtExceptionHandler(prev) }
        assertTrue("uncaught: $uncaught", uncaught.isEmpty())
    }

    @Test
    fun giveUpAtTheTimeout() {
        val resolvers = listOf("slow" to TxtResolver { _, _ -> Thread.sleep(5000); listOf("late") })
        val t0 = System.currentTimeMillis()
        assertEquals(emptyList<String>(), Resolvers.race(resolvers, "n", 500, 0) { true })
        assertTrue(System.currentTimeMillis() - t0 < 2500)
        assertNull(Race.first(emptyList<() -> String?>(), 10, 100))
    }

    @Test
    fun resolversAreInterleavedDotFirst() {
        val cfg = DiscoveryConfig("n", "k", "device-1234567890abcdef",
            dohProviders = listOf("https://doh1/x", "https://doh2/x"), dotServers = listOf("1.1.1.1", "9.9.9.9:8853"),
            do53Servers = emptyList())
        assertEquals(
            listOf("dot:1.1.1.1", "doh:https://doh1/x", "dot:9.9.9.9:8853", "doh:https://doh2/x"),
            Resolvers.build(cfg).map { it.first },
        )
    }

    @Test
    fun dotCanBeSwitchedOff() {
        val cfg = DiscoveryConfig("n", "k", "device-1234567890abcdef", dohProviders = listOf("https://doh1/x"),
            dotServers = emptyList(), do53Servers = emptyList())
        assertEquals(listOf("doh:https://doh1/x"), Resolvers.build(cfg).map { it.first })
    }

    @Test
    fun resolversInterleaveDotDohAndDo53() {
        val cfg = DiscoveryConfig("n", "k", "device-1234567890abcdef",
            dohProviders = listOf("https://doh1/x"), dotServers = listOf("1.1.1.1"), do53Servers = listOf("9.9.9.9"))
        assertEquals(
            listOf("dot:1.1.1.1", "doh:https://doh1/x", "do53:9.9.9.9"),
            Resolvers.build(cfg).map { it.first },
        )
    }

    // ---- plain DNS (port 53): UDP, falling back to TCP when the UDP reply is truncated ----

    private fun id(q: ByteArray) = ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF)

    @Test
    fun do53RoundTripOverUdp() {
        val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        Thread {
            val buf = ByteArray(4096)
            while (!sock.isClosed) {
                val pkt = DatagramPacket(buf, buf.size)
                try { sock.receive(pkt) } catch (_: Exception) { break }
                val r = response(id(buf.copyOf(pkt.length)), "_gs.example.com", listOf(listOf("1/1:payload")))
                try { sock.send(DatagramPacket(r, r.size, pkt.address, pkt.port)) } catch (_: Exception) {}
            }
        }.also { it.isDaemon = true }.start()
        try {
            assertEquals(listOf("1/1:payload"), Do53.query("127.0.0.1", sock.localPort, "_gs.example.com", 2000))
        } finally { sock.close() }
    }

    @Test
    fun do53FallsBackToTcpWhenTheUdpAnswerIsTruncated() {
        // a real DNS server answers UDP and TCP on the same port number; bind both sockets there
        var port = 40000 + (Math.random() * 10000).toInt()
        var udp: DatagramSocket? = null
        for (attempt in 0 until 20) {
            try {
                udp = DatagramSocket(port, InetAddress.getByName("127.0.0.1"))
                break
            } catch (_: Exception) {
                port++
            }
        }
        val u = udp ?: throw IllegalStateException("could not bind a UDP port for the test")
        val ss = ServerSocket(port, 5, InetAddress.getByName("127.0.0.1"))
        Thread {
            val buf = ByteArray(4096)
            while (!u.isClosed) {
                val pkt = DatagramPacket(buf, buf.size)
                try { u.receive(pkt) } catch (_: Exception) { break }
                val r = response(id(buf.copyOf(pkt.length)), "_gs.example.com", listOf(listOf("short")), truncated = true)
                try { u.send(DatagramPacket(r, r.size, pkt.address, pkt.port)) } catch (_: Exception) {}
            }
        }.also { it.isDaemon = true }.start()
        Thread {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: Exception) { break }
                Thread {
                    try {
                        val inp = DataInputStream(c.getInputStream())
                        val q = ByteArray(inp.readUnsignedShort()); inp.readFully(q)
                        val r = response(id(q), "_gs.example.com", listOf(listOf("1/1:full-answer-over-tcp")))
                        c.getOutputStream().write(byteArrayOf((r.size shr 8).toByte(), r.size.toByte()))
                        c.getOutputStream().write(r)
                        c.close()
                    } catch (_: Exception) {
                    }
                }.also { it.isDaemon = true }.start()
            }
        }.also { it.isDaemon = true }.start()
        try {
            assertEquals(listOf("1/1:full-answer-over-tcp"), Do53.query("127.0.0.1", port, "_gs.example.com", 2000))
        } finally { u.close(); ss.close() }
    }

    @Test
    fun do53ServerThatNeverRepliesIsAnError() {
        val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1")) // nothing ever answers
        try {
            try {
                Do53.query("127.0.0.1", sock.localPort, "_gs.example.com", 300)
                fail("silence must be an error")
            } catch (_: Exception) {
            }
        } finally { sock.close() }
    }
}
