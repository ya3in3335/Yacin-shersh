package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Technology fingerprinting and risky HTTP method detection (passive). */
class FingerprintCheck : WebCheck {
    override val id = "fingerprint"
    override val displayName = "Technology Fingerprint"

    private val signatures = listOf(
        "WordPress" to Regex("/wp-(content|includes)/", RegexOption.IGNORE_CASE),
        "Drupal" to Regex("Drupal.settings|/sites/default/files", RegexOption.IGNORE_CASE),
        "Joomla" to Regex("/media/jui/|Joomla!", RegexOption.IGNORE_CASE),
        "Laravel" to Regex("laravel_session|XSRF-TOKEN", RegexOption.IGNORE_CASE),
        "React" to Regex("data-reactroot|react(\\.production|\\.development)?\\.min\\.js", RegexOption.IGNORE_CASE),
        "jQuery" to Regex("jquery[-.]?\\d", RegexOption.IGNORE_CASE)
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val out = mutableListOf<WebFinding>()
        val resp = http.get(baseUrl) ?: return out
        val body = resp.body.take(200_000)
        val detected = linkedSetOf<String>()
        for ((name, pat) in signatures) if (pat.containsMatchIn(body)) detected += name
        Regex("<meta name=[\"']generator[\"'] content=[\"']([^\"']+)", RegexOption.IGNORE_CASE)
            .find(body)?.groupValues?.getOrNull(1)?.let { detected += it.trim() }
        resp.header("x-powered-by")?.split(",")?.forEach { if (it.isNotBlank()) detected += it.trim() }

        if (detected.isNotEmpty()) {
            out += WebFinding(
                code = "fingerprint-stack",
                title = "Technology stack fingerprinted",
                affected = resp.finalUrl,
                detectionMethod = "Passive response analysis",
                evidence = detected.joinToString(", "),
                severity = Severity.INFO,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.INFORMATIONAL,
                reproduction = "Fetch ${resp.finalUrl} and inspect markup/headers for stack indicators.",
                remediation = "Review whether version/stack disclosure is necessary."
            )
        }

        val opt = http.get(baseUrl, method = "OPTIONS")
        if (opt != null) {
            val allow = (opt.header("allow").orEmpty() + " " +
                opt.header("access-control-allow-methods").orEmpty()).uppercase()
            val risky = listOf("PUT", "DELETE", "TRACE", "CONNECT").filter { allow.contains(it) }
            if (risky.isNotEmpty()) {
                out += WebFinding(
                    code = "http-methods",
                    title = "Potentially dangerous HTTP methods enabled: ${risky.joinToString(", ")}",
                    affected = resp.finalUrl,
                    detectionMethod = "OPTIONS request",
                    evidence = "Allow: ${allow.trim()}",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Send OPTIONS ${resp.finalUrl} and read the Allow header.",
                    remediation = "Disable unused HTTP methods (TRACE, PUT, DELETE) at the server/proxy."
                )
            }
        }
        return out
    }
}
