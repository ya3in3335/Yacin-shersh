package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Extended modern security headers (cross-origin isolation, CSP quality). */
class ContentSecurityCheck : WebCheck {
    override val id = "content-security"
    override val displayName = "Extended Security Headers"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val out = mutableListOf<WebFinding>()
        fun has(h: String) = resp.header(h) != null

        val csp = resp.header("content-security-policy")?.lowercase()
        if (csp != null) {
            if (csp.contains("unsafe-inline") || csp.contains("unsafe-eval")) {
                out += finding(
                    "csp-unsafe", "CSP allows unsafe-inline/unsafe-eval", Severity.LOW, resp.finalUrl,
                    "CSP contains unsafe-inline or unsafe-eval",
                    "Remove unsafe-inline/unsafe-eval; use nonces or hashes."
                )
            }
            if (Regex("(script-src|default-src)[^;]*\\*").containsMatchIn(csp)) {
                out += finding(
                    "csp-wildcard", "CSP uses a wildcard source", Severity.LOW, resp.finalUrl,
                    "CSP script/default source includes '*'",
                    "Avoid '*' in script-src/default-src; list explicit origins."
                )
            }
        }

        if (!has("cross-origin-opener-policy")) out += finding(
            "missing-coop", "Missing Cross-Origin-Opener-Policy", Severity.INFO, resp.finalUrl,
            "COOP header absent", "Add 'Cross-Origin-Opener-Policy: same-origin' for isolation."
        )
        if (!has("cross-origin-resource-policy")) out += finding(
            "missing-corp", "Missing Cross-Origin-Resource-Policy", Severity.INFO, resp.finalUrl,
            "CORP header absent", "Add 'Cross-Origin-Resource-Policy: same-origin' where appropriate."
        )
        if (!has("x-permitted-cross-domain-policies")) out += finding(
            "missing-xpcdp", "Missing X-Permitted-Cross-Domain-Policies", Severity.INFO, resp.finalUrl,
            "Header absent", "Add 'X-Permitted-Cross-Domain-Policies: none'."
        )

        resp.header("x-xss-protection")?.let {
            if (it.trim().startsWith("1")) out += finding(
                "legacy-xss-protection", "Legacy X-XSS-Protection enabled", Severity.LOW, resp.finalUrl,
                "X-XSS-Protection: $it",
                "The legacy XSS auditor can introduce issues; set 'X-XSS-Protection: 0' and rely on CSP."
            )
        }
        return out
    }

    private fun finding(code: String, title: String, sev: Severity, url: String, ev: String, fix: String) =
        WebFinding(
            code = code, title = title, affected = url,
            detectionMethod = "Response header inspection", evidence = ev,
            severity = sev, confidence = Confidence.HIGH,
            verification = if (sev == Severity.INFO) VerificationStatus.INFORMATIONAL else VerificationStatus.POTENTIAL,
            reproduction = "Send GET $url and inspect the response headers.", remediation = fix
        )
}
