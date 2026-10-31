package com.gamec.shield

import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/** TLS 1.3 client that trusts exactly one public key (certificate pinning), so a fake node cannot be spliced in. */
internal object PinnedTls {
    private class PinTrust(private val pin: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            throw CertificateException("client auth not supported")

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val spki = chain.firstOrNull()?.publicKey?.encoded
                ?: throw CertificateException("empty chain")
            val got = MessageDigest.getInstance("SHA-256").digest(spki)
            // the compact list carries the first 16 bytes of the hash, the older one all 32
            val want = try { Base64.getDecoder().decode(pin) } catch (_: Exception) { ByteArray(0) }
            if ((want.size != 16 && want.size != 32) || !MessageDigest.isEqual(got.copyOf(want.size), want)) {
                throw CertificateException("pin mismatch")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    fun connect(node: Node, timeoutMs: Int): SSLSocket {
        val ctx = SSLContext.getInstance("TLSv1.3")
        ctx.init(null, arrayOf(PinTrust(node.pinSha256)), null)
        val raw = Socket()
        try {
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(node.host, node.port), timeoutMs)
            raw.soTimeout = timeoutMs
            val s = ctx.socketFactory.createSocket(raw, node.host, node.port, true) as SSLSocket
            s.enabledProtocols = arrayOf("TLSv1.3")
            s.startHandshake()
            s.soTimeout = 0
            return s
        } catch (e: Exception) {
            try { raw.close() } catch (_: Exception) {} // a failed probe or connect must not leak the socket
            throw e
        }
    }
}
