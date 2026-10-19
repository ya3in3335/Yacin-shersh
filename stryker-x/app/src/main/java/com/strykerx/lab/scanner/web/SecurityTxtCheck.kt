package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Checks for a published vulnerability-disclosure policy (RFC 9116 security.txt). */
class SecurityTxtCheck : WebCheck {
    override val id = "security-txt"
    override val displayName = "Disclosure Policy (security.txt)"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()

        for (path in listOf("/.well-known/security.txt", "/security.txt")) {
            val resp = http.get(baseUrl + path) ?: continue
            if (resp.code != 200) continue
            if (ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) continue
            if (!resp.body.contains("Contact", true)) continue
            return listOf(
                WebFinding(
                    code = "security-txt-present",
                    title = "Vulnerability-disclosure policy present (security.txt)",
                    affected = resp.finalUrl,
                    detectionMethod = "well-known path fetch",
                    evidence = resp.body.lineSequence().take(6).joinToString(" | ").take(300),
                    severity = Severity.INFO,
                    confidence = Confidence.HIGH,
                    verification = VerificationStatus.CONFIRMED,
                    reproduction = "Fetch ${resp.finalUrl}.",
                    remediation = "Good practice. Keep the Contact and Expires fields current."
                )
            )
        }
        return listOf(
            WebFinding(
                code = "security-txt-missing",
                title = "No vulnerability-disclosure policy (security.txt)",
                affected = baseUrl,
                detectionMethod = "well-known path fetch",
                evidence = "Neither /.well-known/security.txt nor /security.txt returned a policy.",
                severity = Severity.INFO,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.INFORMATIONAL,
                reproduction = "Fetch $baseUrl/.well-known/security.txt.",
                remediation = "Publish an RFC 9116 security.txt so researchers can report issues responsibly."
            )
        )
    }
}
