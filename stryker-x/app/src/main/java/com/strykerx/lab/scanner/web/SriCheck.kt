package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.URI

/**
 * Subresource Integrity: cross-origin <script>/<link> tags loaded without an
 * integrity attribute can execute attacker-modified code if the third party is
 * compromised. Detection only, by parsing the returned HTML.
 */
class SriCheck : WebCheck {
    override val id = "sri"
    override val displayName = "Subresource Integrity"

    private val scriptTag = Regex("<script\\b[^>]*>", RegexOption.IGNORE_CASE)
    private val linkTag = Regex("<link\\b[^>]*>", RegexOption.IGNORE_CASE)
    private val srcAttr = Regex("""\b(src|href)\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE)

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val baseHost = runCatching { URI(resp.finalUrl).host }.getOrNull() ?: return emptyList()
        val body = resp.body

        val offenders = mutableListOf<String>()
        for (tag in (scriptTag.findAll(body) + linkTag.findAll(body))) {
            val t = tag.value
            if (t.contains("integrity", ignoreCase = true)) continue
            val url = srcAttr.find(t)?.groupValues?.getOrNull(2) ?: continue
            if (!url.startsWith("http://") && !url.startsWith("https://")) continue // same-origin relative
            val host = runCatching { URI(url).host }.getOrNull() ?: continue
            if (host.isNotEmpty() && host != baseHost) offenders.add(url)
        }

        if (offenders.isEmpty()) return emptyList()
        return listOf(
            WebFinding(
                code = "missing-sri",
                title = "Cross-origin resources loaded without Subresource Integrity",
                affected = resp.finalUrl,
                detectionMethod = "HTML parsing of <script>/<link> tags",
                evidence = offenders.distinct().take(5).joinToString(" | ").take(300),
                severity = Severity.LOW,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Inspect the page for third-party <script>/<link> tags that lack an integrity attribute.",
                remediation = "Add integrity (SRI hash) + crossorigin to third-party script/style tags, or self-host them."
            )
        )
    }
}
