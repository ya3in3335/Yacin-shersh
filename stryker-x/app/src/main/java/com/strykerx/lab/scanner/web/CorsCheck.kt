package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * CORS misconfiguration check. Sends a benign probe Origin and inspects the
 * Access-Control-* response. Reflecting an arbitrary Origin together with
 * credentials is a well-known high-impact misconfiguration.
 */
class CorsCheck : WebCheck {
    override val id = "cors"
    override val displayName = "CORS Configuration"

    private val probeOrigin = "https://cherlogons-probe.example"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl, extraHeaders = mapOf("Origin" to probeOrigin)) ?: return emptyList()
        val acao = resp.header("access-control-allow-origin") ?: return emptyList()
        val acac = resp.header("access-control-allow-credentials")?.equals("true", true) == true
        val out = mutableListOf<WebFinding>()

        val reflectsArbitrary = acao == probeOrigin
        val wildcard = acao == "*"

        when {
            reflectsArbitrary && acac -> out += WebFinding(
                code = "cors-reflect-credentials",
                title = "CORS reflects arbitrary Origin with credentials",
                affected = resp.finalUrl,
                detectionMethod = "CORS probe (Origin header reflection)",
                evidence = "ACAO reflected '$probeOrigin'; ACAC=true",
                severity = Severity.HIGH,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Send a request with Origin: $probeOrigin and observe ACAO reflects it while ACAC is true.",
                remediation = "Never reflect arbitrary Origins with credentials; use a strict allowlist."
            )
            reflectsArbitrary -> out += WebFinding(
                code = "cors-reflect",
                title = "CORS reflects arbitrary Origin",
                affected = resp.finalUrl,
                detectionMethod = "CORS probe (Origin header reflection)",
                evidence = "ACAO reflected '$probeOrigin'",
                severity = Severity.MEDIUM,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Send Origin: $probeOrigin and observe ACAO reflects it.",
                remediation = "Validate Origin against a strict allowlist instead of reflecting it."
            )
            wildcard && acac -> out += WebFinding(
                code = "cors-wildcard-credentials",
                title = "CORS wildcard with credentials",
                affected = resp.finalUrl,
                detectionMethod = "CORS response inspection",
                evidence = "ACAO=* with ACAC=true",
                severity = Severity.MEDIUM,
                confidence = Confidence.HIGH,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Observe Access-Control-Allow-Origin: * alongside Allow-Credentials: true.",
                remediation = "'*' with credentials is invalid/unsafe; use explicit trusted origins."
            )
        }
        return out
    }
}
