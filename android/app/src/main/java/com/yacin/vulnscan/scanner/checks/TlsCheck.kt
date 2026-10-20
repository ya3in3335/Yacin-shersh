package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext
import com.yacin.vulnscan.scanner.Severity
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class TlsCheck : Check {
    override val id = "tls"

    private val weak = setOf("TLSv1", "TLSv1.1", "SSLv3", "SSLv2Hello")

    override fun run(ctx: ScanContext): List<Finding> {
        val out = mutableListOf<Finding>()
        val uri = URI(ctx.baseUrl)
        if (uri.scheme != "https") {
            out += Finding(
                id, "Service not served over HTTPS", Severity.MEDIUM, ctx.baseUrl,
                remediation = "Serve all traffic over TLS and redirect HTTP to HTTPS."
            )
            return out
        }
        val host = uri.host ?: return out
        if (host != ctx.scopeHost) return out
        val port = if (uri.port > 0) uri.port else 443

        runCatching {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(host, port) as SSLSocket).use { socket ->
                socket.soTimeout = 8000
                socket.startHandshake()
                val proto = socket.session.protocol
                if (proto in weak) {
                    out += Finding(
                        id, "Weak TLS protocol negotiated: $proto", Severity.HIGH,
                        ctx.baseUrl, remediation = "Disable TLS 1.1 and older; require TLS 1.2+."
                    )
                }
                val cert = socket.session.peerCertificates.firstOrNull() as? X509Certificate
                cert?.let {
                    val days = (it.notAfter.time - System.currentTimeMillis()) / 86_400_000L
                    when {
                        days < 0 -> out += Finding(
                            id, "TLS certificate expired", Severity.HIGH, ctx.baseUrl,
                            evidence = "notAfter=${it.notAfter}",
                            remediation = "Renew the certificate immediately."
                        )
                        days < 15 -> out += Finding(
                            id, "TLS certificate expires soon ($days days)", Severity.LOW,
                            ctx.baseUrl, evidence = "notAfter=${it.notAfter}",
                            remediation = "Renew the certificate before expiry."
                        )
                    }
                }
            }
        }
        return out
    }
}
