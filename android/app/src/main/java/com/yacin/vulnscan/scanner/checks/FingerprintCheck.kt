package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext
import com.yacin.vulnscan.scanner.Severity

class FingerprintCheck : Check {
    override val id = "fingerprint"

    private val signatures = listOf(
        "WordPress" to Regex("/wp-(content|includes)/", RegexOption.IGNORE_CASE),
        "Drupal" to Regex("Drupal.settings|/sites/default/files", RegexOption.IGNORE_CASE),
        "Joomla" to Regex("/media/jui/|Joomla!", RegexOption.IGNORE_CASE),
        "Laravel" to Regex("laravel_session|XSRF-TOKEN", RegexOption.IGNORE_CASE),
        "React" to Regex("data-reactroot|react(\\.production|\\.development)?\\.min\\.js", RegexOption.IGNORE_CASE),
        "jQuery" to Regex("jquery[-.]?\\d", RegexOption.IGNORE_CASE)
    )

    override fun run(ctx: ScanContext): List<Finding> {
        val out = mutableListOf<Finding>()
        val resp = ctx.execute(ctx.baseUrl) ?: return out
        resp.use {
            val body = it.body?.string()?.take(200_000) ?: ""
            val detected = mutableSetOf<String>()
            for ((name, pat) in signatures) if (pat.containsMatchIn(body)) detected += name

            Regex("<meta name=[\"']generator[\"'] content=[\"']([^\"']+)", RegexOption.IGNORE_CASE)
                .find(body)?.groupValues?.getOrNull(1)?.let { g -> detected += g.trim() }

            it.header("x-powered-by")?.split(",")?.forEach { t ->
                if (t.isNotBlank()) detected += t.trim()
            }

            if (detected.isNotEmpty()) {
                out += Finding(
                    id, "Technology stack fingerprinted", Severity.INFO, ctx.baseUrl,
                    evidence = detected.sorted().joinToString(", "),
                    remediation = "Review whether version/stack disclosure is necessary."
                )
            }
        }

        // Risky HTTP methods via OPTIONS
        ctx.execute(ctx.baseUrl, "OPTIONS")?.use {
            val allow = (it.header("Allow").orEmpty() + " " +
                it.header("Access-Control-Allow-Methods").orEmpty()).uppercase()
            val risky = listOf("PUT", "DELETE", "TRACE", "CONNECT").filter { m -> allow.contains(m) }
            if (risky.isNotEmpty()) {
                out += Finding(
                    id, "Dangerous HTTP methods enabled: ${risky.joinToString(", ")}",
                    Severity.MEDIUM, ctx.baseUrl, evidence = "Allow: ${allow.trim()}",
                    remediation = "Disable unused HTTP methods at the server/proxy."
                )
            }
        }
        return out
    }
}
