package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Verifies that plain HTTP is redirected to HTTPS (forced TLS). */
class HttpsRedirectCheck : WebCheck {
    override val id = "https-redirect"
    override val displayName = "HTTPS Enforcement"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        if (!baseUrl.startsWith("https://")) return emptyList()
        val httpUrl = "http://" + baseUrl.removePrefix("https://")
        val resp = http.get(httpUrl) ?: return emptyList()

        // SafeHttp follows redirects (same host) and records the final URL.
        // If the final URL is still plain HTTP and the page loaded, HTTPS is not forced.
        if (resp.code == 200 && resp.finalUrl.startsWith("http://")) {
            return listOf(
                WebFinding(
                    code = "https-not-forced",
                    title = "HTTP is served without redirect to HTTPS",
                    affected = httpUrl,
                    detectionMethod = "Plain-HTTP request + redirect-chain inspection",
                    evidence = "GET $httpUrl returned 200 and stayed on http:// (final: ${resp.finalUrl})",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.HIGH,
                    verification = VerificationStatus.CONFIRMED,
                    reproduction = "Request $httpUrl and observe it serves content over plain HTTP without a 301/302 to https://.",
                    remediation = "Redirect all HTTP traffic to HTTPS (301) and send HSTS."
                )
            )
        }
        return emptyList()
    }
}
