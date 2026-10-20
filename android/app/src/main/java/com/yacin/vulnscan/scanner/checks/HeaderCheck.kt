package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext
import com.yacin.vulnscan.scanner.Severity

class HeaderCheck : Check {
    override val id = "headers"

    private data class Expect(val sev: Severity, val title: String, val fix: String)

    private val expected = mapOf(
        "strict-transport-security" to Expect(
            Severity.MEDIUM, "Missing HSTS header",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        "content-security-policy" to Expect(
            Severity.MEDIUM, "Missing Content-Security-Policy",
            "Define a restrictive CSP to mitigate XSS and injection."
        ),
        "x-content-type-options" to Expect(
            Severity.LOW, "Missing X-Content-Type-Options",
            "Add 'X-Content-Type-Options: nosniff'."
        ),
        "x-frame-options" to Expect(
            Severity.LOW, "Missing X-Frame-Options / frame-ancestors",
            "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors'."
        ),
        "referrer-policy" to Expect(
            Severity.INFO, "Missing Referrer-Policy",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
        )
    )

    private val leaky = listOf("server", "x-powered-by", "x-aspnet-version")

    override fun run(ctx: ScanContext): List<Finding> {
        val out = mutableListOf<Finding>()
        val resp = ctx.execute(ctx.baseUrl) ?: return out
        resp.use {
            val headers = it.headers
            val present = headers.names().map { n -> n.lowercase() }.toSet()
            val csp = headers["content-security-policy"]?.lowercase() ?: ""

            for ((name, e) in expected) {
                if (name == "x-frame-options" && csp.contains("frame-ancestors")) continue
                if (name !in present) {
                    out += Finding(id, e.title, e.sev, ctx.baseUrl, remediation = e.fix)
                }
            }
            for (name in leaky) {
                headers[name]?.let { v ->
                    out += Finding(
                        id, "Information disclosure via '$name' header",
                        Severity.LOW, ctx.baseUrl, evidence = "$name: $v",
                        remediation = "Remove or obfuscate the '$name' response header."
                    )
                }
            }
            for (cookie in headers.values("Set-Cookie")) {
                val low = cookie.lowercase()
                val cname = cookie.substringBefore("=").trim()
                val missing = buildList {
                    if (!low.contains("secure")) add("Secure")
                    if (!low.contains("httponly")) add("HttpOnly")
                    if (!low.contains("samesite")) add("SameSite")
                }
                if (missing.isNotEmpty()) {
                    out += Finding(
                        id, "Cookie '$cname' missing flags: ${missing.joinToString(", ")}",
                        Severity.LOW, ctx.baseUrl, evidence = cookie.take(120),
                        remediation = "Set Secure, HttpOnly and SameSite on session cookies."
                    )
                }
            }
        }
        return out
    }
}
