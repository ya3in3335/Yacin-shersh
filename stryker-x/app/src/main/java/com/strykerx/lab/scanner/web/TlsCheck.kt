package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** TLS posture: HTTPS enforcement, weak protocol, certificate validity. */
class TlsCheck : WebCheck {
    override val id = "tls"
    override val displayName = "TLS / Certificate"

    private val weak = setOf("TLSv1", "TLSv1.1", "SSLv3", "SSLv2Hello")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val out = mutableListOf<WebFinding>()
        val uri = runCatching { URI(baseUrl) }.getOrNull() ?: return out

        if (uri.scheme != "https") {
            out += WebFinding(
                code = "tls-no-https",
                title = "Service not served over HTTPS",
                affected = baseUrl,
                detectionMethod = "URL scheme inspection",
                evidence = "Scheme is '${uri.scheme}'",
                severity = Severity.MEDIUM,
                confidence = Confidence.HIGH,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Observe that the target is reachable over plain HTTP.",
                remediation = "Serve all traffic over TLS and redirect HTTP to HTTPS."
            )
            return out
        }

        val host = uri.host ?: return out
        val port = if (uri.port > 0) uri.port else 443

        runCatching {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(host, port) as SSLSocket).use { socket ->
                socket.soTimeout = 8000
                socket.startHandshake()
                val proto = socket.session.protocol
                if (proto in weak) {
                    out += WebFinding(
                        code = "tls-weak-protocol",
                        title = "Weak TLS protocol negotiated: $proto",
                        affected = "$host:$port",
                        detectionMethod = "TLS handshake",
                        evidence = "Negotiated $proto",
                        severity = Severity.HIGH,
                        confidence = Confidence.HIGH,
                        verification = VerificationStatus.CONFIRMED,
                        reproduction = "Handshake with $host:$port and observe the negotiated protocol.",
                        remediation = "Disable TLS 1.1 and older; require TLS 1.2+."
                    )
                }
                val cert = socket.session.peerCertificates.firstOrNull() as? X509Certificate
                cert?.let {
                    val days = (it.notAfter.time - System.currentTimeMillis()) / 86_400_000L
                    when {
                        days < 0 -> out += cert("tls-expired",
                            "TLS certificate expired", Severity.HIGH, host, port,
                            "notAfter=${it.notAfter}", VerificationStatus.CONFIRMED,
                            "Renew the certificate immediately.")
                        days < 15 -> out += cert("tls-expiring",
                            "TLS certificate expires soon ($days days)", Severity.LOW, host, port,
                            "notAfter=${it.notAfter}", VerificationStatus.POTENTIAL,
                            "Renew the certificate before expiry.")
                    }
                }
            }
        }
        return out
    }

    private fun cert(
        code: String, title: String, sev: Severity, host: String, port: Int,
        evidence: String, status: VerificationStatus, fix: String
    ) = WebFinding(
        code = code, title = title, affected = "$host:$port",
        detectionMethod = "TLS certificate inspection", evidence = evidence,
        severity = sev, confidence = Confidence.HIGH, verification = status,
        reproduction = "Inspect the certificate presented by $host:$port.", remediation = fix
    )
}
