package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Flags responses that set a session cookie yet permit caching of the body. */
class CacheControlCheck : WebCheck {
    override val id = "cache-control"
    override val displayName = "Sensitive Caching"

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val setsCookie = resp.headerValues("set-cookie").isNotEmpty()
        if (!setsCookie) return emptyList()
        val cc = resp.header("cache-control")?.lowercase().orEmpty()
        val pragma = resp.header("pragma")?.lowercase().orEmpty()
        val cacheable = !(cc.contains("no-store") || cc.contains("private") || pragma.contains("no-cache"))
        if (!cacheable) return emptyList()
        return listOf(
            WebFinding(
                code = "cache-sensitive",
                title = "Response sets a cookie but allows caching",
                affected = resp.finalUrl,
                detectionMethod = "Passive header analysis",
                evidence = "Set-Cookie present; Cache-Control: ${cc.ifBlank { "(none)" }}. Shared/proxy caches may store an authenticated response.",
                severity = Severity.LOW,
                confidence = Confidence.LOW,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Fetch ${resp.finalUrl} and inspect Cache-Control vs Set-Cookie.",
                remediation = "Send 'Cache-Control: no-store' (and private) on responses that carry session cookies or personal data."
            )
        )
    }
}
