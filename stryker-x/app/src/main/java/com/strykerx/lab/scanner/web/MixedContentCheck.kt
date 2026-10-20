package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Detects insecure (http://) subresources loaded by an HTTPS page — mixed content. */
class MixedContentCheck : WebCheck {
    override val id = "mixed-content"
    override val displayName = "Mixed Content"

    private val resource = Regex(
        """(?:src|href|action)\s*=\s*["'](http://[^"']+)["']""", RegexOption.IGNORE_CASE
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        if (!baseUrl.startsWith("https://", true)) return emptyList()
        val resp = http.get(baseUrl) ?: return emptyList()
        val body = resp.body.take(400_000)
        val hits = resource.findAll(body)
            .map { it.groupValues[1] }
            .filterNot { it.startsWith("http://www.w3.org") || it.startsWith("http://schema.org") }
            .distinct().take(20).toList()
        if (hits.isEmpty()) return emptyList()
        val active = hits.any { it.endsWith(".js", true) || it.contains(".js?") }
        return listOf(
            WebFinding(
                code = "mixed-content",
                title = "Mixed content: HTTPS page loads ${hits.size} insecure http:// resource(s)",
                affected = resp.finalUrl,
                detectionMethod = "Passive HTML analysis",
                evidence = hits.joinToString("  |  ").take(900),
                severity = if (active) Severity.MEDIUM else Severity.LOW,
                confidence = Confidence.HIGH,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Fetch ${resp.finalUrl} and grep for http:// in src/href/action attributes.",
                remediation = "Serve all subresources over HTTPS. Active mixed content (scripts) can be intercepted and rewritten (MITM)."
            )
        )
    }
}
