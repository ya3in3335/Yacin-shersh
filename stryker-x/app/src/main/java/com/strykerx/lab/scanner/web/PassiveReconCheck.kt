package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.InetAddress
import java.net.URI

/**
 * Passive reconnaissance: DNS records, mixed-content, and detection of
 * secrets/tokens accidentally exposed in the returned page. Purely read-only.
 */
class PassiveReconCheck : WebCheck {
    override val id = "recon"
    override val displayName = "Passive Recon"

    // Patterns for secrets that should never appear in a public response.
    private val secretPatterns = listOf(
        "AWS access key" to Regex("AKIA[0-9A-Z]{16}"),
        "Google API key" to Regex("AIza[0-9A-Za-z_\\-]{35}"),
        "Slack token" to Regex("xox[baprs]-[0-9A-Za-z\\-]{10,}"),
        "Private key block" to Regex("-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "JWT" to Regex("eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}"),
        "Generic secret assignment" to Regex("(?i)(api[_-]?key|secret|password|token)\\s*[:=]\\s*[\"'][^\"']{8,}[\"']")
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val out = mutableListOf<WebFinding>()
        val host = runCatching { URI(baseUrl).host }.getOrNull()

        if (host != null) {
            val addrs = runCatching { InetAddress.getAllByName(host).map { it.hostAddress } }
                .getOrDefault(emptyList())
            if (addrs.isNotEmpty()) {
                out += WebFinding(
                    code = "recon-dns",
                    title = "Resolved network addresses",
                    affected = host,
                    detectionMethod = "DNS resolution (A/AAAA)",
                    evidence = addrs.distinct().joinToString(", "),
                    severity = Severity.INFO,
                    confidence = Confidence.HIGH,
                    verification = VerificationStatus.INFORMATIONAL,
                    reproduction = "Resolve $host and list its A/AAAA records.",
                    remediation = "Informational — confirms the resolved infrastructure."
                )
            }
        }

        val resp = http.get(baseUrl) ?: return out
        val body = resp.body

        // Mixed content on an HTTPS page.
        if (resp.finalUrl.startsWith("https://")) {
            val mixed = Regex("""(src|href)\s*=\s*["']http://[^"']+""", RegexOption.IGNORE_CASE)
                .findAll(body).map { it.value }.take(3).toList()
            if (mixed.isNotEmpty()) {
                out += WebFinding(
                    code = "recon-mixed-content",
                    title = "Mixed content: insecure resources on an HTTPS page",
                    affected = resp.finalUrl,
                    detectionMethod = "HTML body inspection",
                    evidence = mixed.joinToString(" | ").take(200),
                    severity = Severity.LOW,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Load the page and look for http:// subresources.",
                    remediation = "Serve all subresources over HTTPS."
                )
            }
        }

        // Secret/token exposure.
        for ((label, pattern) in secretPatterns) {
            val m = pattern.find(body) ?: continue
            val sample = m.value.take(12) + "…"
            out += WebFinding(
                code = "recon-secret-${label.hashCode()}",
                title = "Possible secret exposed in response: $label",
                affected = resp.finalUrl,
                detectionMethod = "Response body pattern match",
                evidence = "Matched $label pattern (redacted sample: $sample)",
                severity = Severity.HIGH,
                confidence = Confidence.LOW,
                // Pattern match alone is not proof; a human must confirm it is a
                // live secret and not a placeholder/example -> POTENTIAL.
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Fetch $baseUrl and search the body for a $label pattern; confirm it is a real, active secret.",
                remediation = "Remove the secret from client-facing responses and rotate it if valid."
            )
        }
        return out
    }
}
