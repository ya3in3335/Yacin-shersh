package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * robots.txt recon: surfaces Disallow entries that reveal sensitive-looking
 * paths (admin, backup, config, internal). Informational — it only reads a
 * public, intentionally published file.
 */
class RobotsReconCheck : WebCheck {
    override val id = "robots-recon"
    override val displayName = "robots.txt Recon"

    private val interesting = listOf(
        "admin", "backup", "config", "private", "internal", "secret", "login",
        "dashboard", "api", "upload", "test", "staging", "db", "sql", ".git"
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get("$baseUrl/robots.txt") ?: return emptyList()
        if (resp.code != 200) return emptyList()
        val body = resp.body
        if (!body.contains("Disallow", ignoreCase = true)) return emptyList()

        val disallowed = body.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("Disallow:", ignoreCase = true) }
            .map { it.substringAfter(":").trim() }
            .filter { it.isNotEmpty() && it != "/" }
            .toList()

        val sensitive = disallowed.filter { path ->
            interesting.any { path.contains(it, ignoreCase = true) }
        }
        if (sensitive.isEmpty()) return emptyList()

        return listOf(
            WebFinding(
                code = "robots-sensitive-paths",
                title = "robots.txt advertises sensitive-looking paths",
                affected = "$baseUrl/robots.txt",
                detectionMethod = "robots.txt Disallow analysis",
                evidence = sensitive.take(10).joinToString(", ").take(300),
                severity = Severity.INFO,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.INFORMATIONAL,
                reproduction = "Read $baseUrl/robots.txt and review the Disallow entries.",
                remediation = "Do not rely on robots.txt to hide sensitive paths; it is public. Protect them with authentication."
            )
        )
    }
}
