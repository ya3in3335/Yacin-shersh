package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Security response-header and cookie-flag hygiene. */
class HeaderCheck : WebCheck {
    override val id = "security-headers"
    override val displayName = "Security Headers"

    private data class Expect(val sev: Severity, val title: String, val fix: String)

    private val expected = mapOf(
        "strict-transport-security" to Expect(
            Severity.MEDIUM, "Missing HSTS header",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        "content-security-policy" to Expect(
            Severity.MEDIUM, "Missing Content-Security-Policy",
            "Define a restrictive CSP to mitigate XSS and data injection."
        ),
        "x-content-type-options" to Expect(
            Severity.LOW, "Missing X-Content-Type-Options",
            "Add 'X-Content-Type-Options: nosniff'."
        ),
        "x-frame-options" to Expect(
            Severity.LOW, "Missing X-Frame-Options / frame-ancestors",
            "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."
        ),
        "referrer-policy" to Expect(
            Severity.INFO, "Missing Referrer-Policy",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
        ),
        "permissions-policy" to Expect(
            Severity.INFO, "Missing Permissions-Policy",
            "Define a Permissions-Policy to restrict powerful browser features."
        )
    )

    private val leaky = listOf("server", "x-powered-by", "x-aspnet-version")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val out = mutableListOf<WebFinding>()
        val present = resp.headers.keys.map { it.lowercase() }.toSet()
        val csp = resp.header("content-security-policy")?.lowercase().orEmpty()

        for ((name, e) in expected) {
            if (name == "x-frame-options" && csp.contains("frame-ancestors")) continue
            if (name !in present) {
                out += WebFinding(
                    code = "hdr-missing-$name",
                    title = e.title,
                    affected = resp.finalUrl,
                    detectionMethod = "Response header inspection",
                    evidence = "Header '$name' absent in response from ${resp.finalUrl}",
                    severity = e.sev,
                    confidence = Confidence.HIGH,
                    // Missing hardening headers are a real, directly-observed config gap,
                    // but not themselves an exploit -> POTENTIAL, not CONFIRMED.
                    verification = if (e.sev == Severity.INFO)
                        VerificationStatus.INFORMATIONAL else VerificationStatus.POTENTIAL,
                    reproduction = "Send GET ${resp.finalUrl} and observe the response headers.",
                    remediation = e.fix
                )
            }
        }

        for (name in leaky) {
            resp.header(name)?.let { v ->
                out += WebFinding(
                    code = "hdr-disclosure-$name",
                    title = "Information disclosure via '$name' header",
                    affected = resp.finalUrl,
                    detectionMethod = "Response header inspection",
                    evidence = "$name: $v",
                    severity = Severity.LOW,
                    confidence = Confidence.HIGH,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Send GET ${resp.finalUrl} and read the '$name' header.",
                    remediation = "Remove or obfuscate the '$name' response header."
                )
            }
        }

        for (cookie in resp.headerValues("set-cookie")) {
            val low = cookie.lowercase()
            val cname = cookie.substringBefore("=").trim()
            val missing = buildList {
                if (!low.contains("secure")) add("Secure")
                if (!low.contains("httponly")) add("HttpOnly")
                if (!low.contains("samesite")) add("SameSite")
            }
            if (missing.isNotEmpty()) {
                out += WebFinding(
                    code = "cookie-flags-$cname",
                    title = "Cookie '$cname' missing flags: ${missing.joinToString(", ")}",
                    affected = resp.finalUrl,
                    detectionMethod = "Set-Cookie inspection",
                    evidence = cookie.take(160),
                    severity = Severity.LOW,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Inspect the Set-Cookie header for '$cname'.",
                    remediation = "Set Secure, HttpOnly and SameSite on session cookies."
                )
            }
        }
        return out
    }
}
