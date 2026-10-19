package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * Passive sensitive-data exposure in the returned HTML/JS: hardcoded secrets,
 * internal IPs, stack traces and risky developer comments. High-value, read-only.
 */
class SensitiveDataCheck : WebCheck {
    override val id = "sensitive-data"
    override val displayName = "Sensitive Data Exposure"

    private val patterns = listOf(
        Triple("AWS access key", Regex("AKIA[0-9A-Z]{16}"), Severity.HIGH),
        Triple("Google API key", Regex("AIza[0-9A-Za-z_\\-]{35}"), Severity.HIGH),
        Triple("Google OAuth client secret", Regex("GOCSPX-[0-9A-Za-z_\\-]{20,}"), Severity.HIGH),
        Triple("Stripe live secret key", Regex("sk_live_[0-9a-zA-Z]{24,}"), Severity.HIGH),
        Triple("Slack token", Regex("xox[baprs]-[0-9A-Za-z\\-]{10,}"), Severity.HIGH),
        Triple("JSON Web Token", Regex("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"), Severity.MEDIUM),
        Triple("Private key block", Regex("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.HIGH),
        Triple("Internal/private IP", Regex("\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})\\b"), Severity.LOW),
        Triple("Stack trace / debug error", Regex("(?i)(stack trace|at [\\w.$]+\\([\\w.]+\\.(java|kt|php|py):\\d+\\)|Traceback \\(most recent call last\\))"), Severity.MEDIUM)
    )

    private val riskyComment = Regex(
        "(?is)<!--.*?(password|passwd|todo|fixme|hack|secret|api[_-]?key|backdoor|debug).*?-->"
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val body = resp.body.take(600_000)
        val out = mutableListOf<WebFinding>()

        for ((label, rx, sev) in patterns) {
            val m = rx.find(body) ?: continue
            out += WebFinding(
                code = "leak-${label.hashCode()}",
                title = "Sensitive data in response: $label",
                affected = resp.finalUrl,
                detectionMethod = "Passive response content scan",
                evidence = "Matched $label (redacted): " + redact(m.value),
                severity = sev,
                confidence = if (sev == Severity.HIGH) Confidence.MEDIUM else Confidence.LOW,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Fetch ${resp.finalUrl} and search the body for the $label pattern.",
                remediation = "Remove secrets/internal details from client-delivered content; rotate any exposed credential."
            )
        }

        val comments = riskyComment.findAll(body).map { it.value }.take(5).toList()
        if (comments.isNotEmpty()) {
            out += WebFinding(
                code = "leak-html-comments",
                title = "Risky HTML comments (developer notes / possible secrets)",
                affected = resp.finalUrl,
                detectionMethod = "Passive response content scan",
                evidence = comments.joinToString("  |  ") { it.replace('\n', ' ').take(160) }.take(900),
                severity = Severity.LOW,
                confidence = Confidence.LOW,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Fetch ${resp.finalUrl} and read HTML comments.",
                remediation = "Strip developer comments from production HTML."
            )
        }
        return out
    }

    private fun redact(v: String): String =
        if (v.length <= 12) v.take(4) + "…" else v.take(8) + "…(${v.length} chars)"
}
