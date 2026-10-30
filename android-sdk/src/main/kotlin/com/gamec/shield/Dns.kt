package com.gamec.shield

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** The few bytes of DNS wire format needed to ask for TXT records and read the answer (RFC 1035). */
internal object DnsWire {
    private const val TYPE_TXT = 16
    private const val CLASS_IN = 1

    fun buildQuery(name: String, id: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun u16(v: Int) { out.write(v shr 8); out.write(v and 0xFF) }
        u16(id)
        u16(0x0100) // standard query, recursion desired
        u16(1); u16(0); u16(0); u16(0)
        for (label in name.trimEnd('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            require(b.isNotEmpty() && b.size <= 63) { "bad DNS label in $name" }
            out.write(b.size)
            out.write(b)
        }
        out.write(0)
        u16(TYPE_TXT)
        u16(CLASS_IN)
        return out.toByteArray()
    }

    /** TXT values in the answer (strings of one record joined). Empty for "no such name"; throws if malformed. */
    fun parseTxt(msg: ByteArray, expectId: Int): List<String> {
        if (msg.size < 12) throw IllegalArgumentException("short DNS message")
        fun u8(p: Int) = msg[p].toInt() and 0xFF
        fun u16(p: Int) = (u8(p) shl 8) or u8(p + 1)
        if (u16(0) != expectId) throw IllegalArgumentException("DNS id mismatch")
        val flags = u16(2)
        if (flags and 0x8000 == 0) throw IllegalArgumentException("not a response")
        when (flags and 0xF) {
            0 -> {}
            3 -> return emptyList() // NXDOMAIN
            else -> throw IllegalArgumentException("DNS error code ${flags and 0xF}")
        }
        val qd = u16(4)
        val an = u16(6)

        fun skipName(start: Int): Int {
            var p = start
            while (true) {
                if (p >= msg.size) throw IllegalArgumentException("name runs past the message")
                val len = u8(p)
                when {
                    len == 0 -> return p + 1
                    len and 0xC0 == 0xC0 -> return p + 2 // compression pointer ends the name
                    else -> p += 1 + len
                }
            }
        }

        var pos = 12
        repeat(qd) { pos = skipName(pos) + 4 }
        val out = ArrayList<String>()
        repeat(an) {
            pos = skipName(pos)
            if (pos + 10 > msg.size) throw IllegalArgumentException("truncated answer")
            val type = u16(pos)
            val rdLen = u16(pos + 8)
            pos += 10
            if (pos + rdLen > msg.size) throw IllegalArgumentException("truncated rdata")
            if (type == TYPE_TXT) {
                val sb = StringBuilder()
                var p = pos
                val end = pos + rdLen
                while (p < end) {
                    val n = u8(p)
                    if (p + 1 + n > end) throw IllegalArgumentException("bad TXT string")
                    sb.append(String(msg, p + 1, n, Charsets.ISO_8859_1))
                    p += 1 + n
                }
                out += sb.toString()
            }
            pos += rdLen
        }
        return out
    }
}

/** DNS over TLS (RFC 7858): the same wire messages, framed with a 2-byte length, over TLS on port 853. */
internal object Dot {
    private val random = SecureRandom()

    fun query(
        host: String,
        port: Int,
        name: String,
        timeoutMs: Int,
        connect: (String, Int, Int) -> Socket = ::tlsConnect,
    ): List<String> {
        val id = random.nextInt(0x10000)
        connect(host, port, timeoutMs).use { s ->
            s.soTimeout = timeoutMs
            val q = DnsWire.buildQuery(name, id)
            val out = s.getOutputStream()
            out.write(byteArrayOf((q.size shr 8).toByte(), q.size.toByte()))
            out.write(q)
            out.flush()
            val inp = DataInputStream(s.getInputStream())
            val resp = ByteArray(inp.readUnsignedShort())
            inp.readFully(resp)
            return DnsWire.parseTxt(resp, id)
        }
    }

    /** TLS with the system trust store; the certificate must match [host] (an IP address works if it is in the SAN). */
    fun tlsConnect(host: String, port: Int, timeoutMs: Int): Socket {
        val raw = Socket()
        try {
            raw.connect(InetSocketAddress(host, port), timeoutMs)
            raw.soTimeout = timeoutMs
            val s = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, port, true) as SSLSocket
            val p = s.sslParameters
            p.endpointIdentificationAlgorithm = "HTTPS"
            s.sslParameters = p
            s.startHandshake()
            return s
        } catch (e: Exception) {
            try { raw.close() } catch (_: Exception) {}
            throw e
        }
    }
}

/** Plain DNS (RFC 1035): UDP on port 53, falling back to TCP when the UDP reply is truncated (TC bit). */
internal object Do53 {
    private val random = SecureRandom()

    fun query(host: String, port: Int = 53, name: String, timeoutMs: Int): List<String> {
        val id = random.nextInt(0x10000)
        val q = DnsWire.buildQuery(name, id)
        val addr = InetAddress.getByName(host)
        DatagramSocket().use { sock ->
            sock.soTimeout = timeoutMs
            sock.send(DatagramPacket(q, q.size, addr, port))
            val buf = ByteArray(4096)
            val pkt = DatagramPacket(buf, buf.size)
            sock.receive(pkt)
            if (!truncated(buf, pkt.length)) return DnsWire.parseTxt(buf.copyOf(pkt.length), id)
        }
        return queryTcp(host, port, q, id, timeoutMs) // UDP reply did not fit: redo it over TCP
    }

    private fun truncated(msg: ByteArray, len: Int): Boolean {
        if (len < 4) return false
        val flags = ((msg[2].toInt() and 0xFF) shl 8) or (msg[3].toInt() and 0xFF)
        return flags and 0x0200 != 0
    }

    private fun queryTcp(host: String, port: Int, q: ByteArray, id: Int, timeoutMs: Int): List<String> {
        Socket().use { s ->
            s.connect(InetSocketAddress(host, port), timeoutMs)
            s.soTimeout = timeoutMs
            val out = s.getOutputStream()
            out.write(byteArrayOf((q.size shr 8).toByte(), q.size.toByte()))
            out.write(q)
            out.flush()
            val inp = DataInputStream(s.getInputStream())
            val resp = ByteArray(inp.readUnsignedShort())
            inp.readFully(resp)
            return DnsWire.parseTxt(resp, id)
        }
    }
}
