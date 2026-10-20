package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.URLEncoder

/**
 * Opt-in open-redirect probe. Only parameters that already exist in the URL and
 * whose names look like redirect targets are tested, with a benign external
 * marker. Detection only — it inspects the Location header, never follows it.
 * Gated behind the operator's active-tests authorization.
 */
class OpenRedirectCheck : WebCheck {
    override val id = "open-redirect"
    override val displayName = "Open Redirect (opt-in)"

    private val redirectParams = setOf(
        "url", "next", "redirect", "redirect_url", "return", "returnurl", "return_url",
        "dest", "destination", "continue", "goto", "target", "r", "u"
    )
    private val marker = "cherlogons-redirect-probe.example"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val qIndex = baseUrl.indexOf('?')
        if (qIndex < 0) return emptyList()
        val base = baseUrl.substring(0, qIndex)
        val params = baseUrl.substring(qIndex + 1).split("&").mapNotNull {
            val i = it.indexOf('='); if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
        }
        val targets = params.filter { it.first.lowercase() in redirectParams }
        if (targets.isEmpty()) return emptyList()

        val out = mutableListOf<WebFinding>()
        for ((key, _) in targets) {
            val payload = "https://$marker/"
            val q = params.joinToString("&") { (k, v) ->
                "${enc(k)}=${enc(if (k == key) payload else v)}"
            }
            val url = "$base?$q"
            val resp = http.get(url) ?: continue
            val location = resp.header("location") ?: continue
            if (location.contains(marker)) {
                out += WebFinding(
                    code = "open-redirect-$key",
                    title = "Possible open redirect via parameter '$key'",
                    affected = url,
                    detectionMethod = "Redirect-parameter probe (Location header inspection)",
                    evidence = "Location header pointed to the external marker: ${location.take(120)}",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Set '$key' to an external URL and observe the Location header redirecting off-site.",
                    remediation = "Validate redirect targets against an allowlist of internal paths/hosts."
                )
            }
        }
        return out
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}
