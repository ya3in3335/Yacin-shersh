package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus

/**
 * Analyst-style correlation: an experienced tester does not just list isolated
 * findings — they connect them into higher-level risks. This pure engine reads
 * the raw findings and emits derived "insight" findings ONLY when the component
 * conditions are actually present (never fabricated).
 */
object CorrelationEngine {

    fun correlate(findings: List<WebFinding>): List<WebFinding> {
        if (findings.isEmpty()) return emptyList()
        val codes = findings.map { it.code }
        fun has(prefix: String) = codes.any { it.startsWith(prefix) }

        val missingCsp = has("hdr-missing-content-security-policy")
        val reflectedXss = has("xss-")
        val weakCookies = has("cookie-flags")
        val httpsNotForced = has("https-not-forced")
        val hstsMissing = has("hdr-missing-strict-transport-security")
        val sqli = has("sqli-")
        val highExposures = findings.count {
            it.code.startsWith("exposure-") && it.severity == Severity.HIGH &&
                it.verification == VerificationStatus.CONFIRMED
        }

        val out = mutableListOf<WebFinding>()

        if (reflectedXss && missingCsp) {
            out += insight(
                "insight-xss-no-csp", "Elevated XSS exposure: reflected input with no CSP",
                Severity.HIGH,
                "Reflected input (XSS probe) combined with a missing Content-Security-Policy means a successful XSS has no second line of defense.",
                "Fix the reflection (output-encode) AND deploy a strict CSP as defense-in-depth."
            )
        }
        if (reflectedXss && weakCookies) {
            out += insight(
                "insight-xss-cookie", "Session-theft risk: XSS reachable + weak cookie flags",
                Severity.HIGH,
                "Reflected input plus cookies missing HttpOnly/SameSite means an XSS could read or abuse the session cookie.",
                "Set HttpOnly + SameSite on session cookies and remove the reflection."
            )
        }
        if (httpsNotForced && hstsMissing) {
            out += insight(
                "insight-downgrade", "Downgrade / MITM risk: HTTP not forced and no HSTS",
                Severity.MEDIUM,
                "Plain HTTP is served without a redirect and HSTS is absent, so a network attacker can strip TLS.",
                "Redirect all HTTP to HTTPS (301) and send Strict-Transport-Security."
            )
        }
        if (highExposures >= 2) {
            out += insight(
                "insight-leak-cluster", "Sensitive-file leak cluster ($highExposures files)",
                Severity.HIGH,
                "Several sensitive files were reachable; together they often reveal credentials, source, or infrastructure.",
                "Remove all exposed files from the web root and rotate any leaked secrets."
            )
        }
        if (sqli && weakCookies) {
            out += insight(
                "insight-sqli-context", "Injection + weak session handling",
                Severity.HIGH,
                "A possible injection point alongside weak cookie protection compounds account-takeover risk.",
                "Parameterize all queries and harden session cookies."
            )
        }
        return out
    }

    private fun insight(code: String, title: String, sev: Severity, detail: String, fix: String) =
        WebFinding(
            code = code,
            title = title,
            affected = "(correlated)",
            detectionMethod = "Analyst correlation of multiple findings",
            evidence = detail,
            severity = sev,
            confidence = Confidence.MEDIUM,
            // Correlations are analytical conclusions, not direct observations.
            verification = VerificationStatus.POTENTIAL,
            reproduction = "Review the component findings that triggered this correlation together.",
            remediation = fix
        )
}
