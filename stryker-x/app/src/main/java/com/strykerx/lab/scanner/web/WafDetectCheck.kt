package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * Detects a WAF / CDN in front of the site from response headers. Informational
 * context an experienced tester always notes: it shapes how other findings are
 * interpreted (some protections may be provided by the edge, not the origin).
 */
class WafDetectCheck : WebCheck {
    override val id = "waf"
    override val displayName = "WAF / CDN Detection"

    // header name (lowercase) or header-value fragment -> product
    private val headerNames = mapOf(
        "cf-ray" to "Cloudflare",
        "x-sucuri-id" to "Sucuri",
        "x-akamai-transformed" to "Akamai",
        "x-cdn" to "Generic CDN",
        "x-amz-cf-id" to "AWS CloudFront",
        "x-iinfo" to "Imperva Incapsula",
        "x-cache" to "CDN cache layer"
    )
    private val serverValues = mapOf(
        "cloudflare" to "Cloudflare",
        "akamaighost" to "Akamai",
        "awselb" to "AWS ELB",
        "sucuri" to "Sucuri",
        "fastly" to "Fastly",
        "incapsula" to "Imperva Incapsula"
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val detected = linkedSetOf<String>()

        val present = resp.headers.keys.map { it.lowercase() }.toSet()
        for ((name, product) in headerNames) if (name in present) detected += product

        val server = resp.header("server")?.lowercase().orEmpty()
        val powered = resp.header("x-powered-by")?.lowercase().orEmpty()
        for ((frag, product) in serverValues) {
            if (server.contains(frag) || powered.contains(frag)) detected += product
        }

        if (detected.isEmpty()) return emptyList()
        return listOf(
            WebFinding(
                code = "waf-detected",
                title = "Edge protection detected: ${detected.joinToString(", ")}",
                affected = resp.finalUrl,
                detectionMethod = "Response header analysis",
                evidence = detected.joinToString(", "),
                severity = Severity.INFO,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.INFORMATIONAL,
                reproduction = "Inspect response headers for CDN/WAF fingerprints.",
                remediation = "Informational: some security controls may be enforced at the edge rather than the origin."
            )
        )
    }
}
