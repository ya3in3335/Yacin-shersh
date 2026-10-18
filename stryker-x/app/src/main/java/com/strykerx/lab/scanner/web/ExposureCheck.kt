package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Detect commonly-exposed sensitive files. Signature-gated to avoid SPA false 200s. */
class ExposureCheck : WebCheck {
    override val id = "exposure"
    override val displayName = "Exposed Files"

    private data class Probe(val sev: Severity, val title: String, val signatures: List<String>)

    private val paths = mapOf(
        "/.git/HEAD" to Probe(Severity.HIGH, "Exposed .git repository", listOf("ref:", "refs/heads")),
        "/.env" to Probe(Severity.HIGH, "Exposed .env file", listOf("APP_", "DB_", "SECRET", "KEY=")),
        "/wp-config.php.bak" to Probe(Severity.HIGH, "Exposed WordPress config backup", listOf("DB_PASSWORD", "DB_USER")),
        "/phpinfo.php" to Probe(Severity.MEDIUM, "Exposed phpinfo()", listOf("PHP Version", "phpinfo")),
        "/server-status" to Probe(Severity.MEDIUM, "Exposed Apache server-status", listOf("Apache Server Status")),
        "/.svn/entries" to Probe(Severity.MEDIUM, "Exposed .svn metadata", listOf("svn", "dir")),
        "/security.txt" to Probe(Severity.INFO, "security.txt present", listOf("Contact:", "Policy:")),
        "/robots.txt" to Probe(Severity.INFO, "robots.txt present", listOf("Disallow", "User-agent"))
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val out = mutableListOf<WebFinding>()
        for ((path, probe) in paths) {
            val url = baseUrl + path
            val resp = http.get(url) ?: continue
            if (resp.code != 200) continue
            val body = resp.body.take(4096)
            if (probe.signatures.none { body.contains(it) }) continue
            val informational = probe.sev == Severity.INFO
            out += WebFinding(
                code = "exposure-$path",
                title = probe.title,
                affected = url,
                detectionMethod = "Authorized path probe (GET)",
                evidence = if (informational) body.take(200)
                else "HTTP 200 with content signature at $path",
                severity = probe.sev,
                confidence = Confidence.HIGH,
                // A reachable sensitive file with a matching signature is directly
                // observed and reproducible -> CONFIRMED (informational items stay INFO).
                verification = if (informational)
                    VerificationStatus.INFORMATIONAL else VerificationStatus.CONFIRMED,
                reproduction = "Send GET $url and verify a 200 response containing the signature.",
                remediation = "Remove the file from the web root or block external access to it."
            )
        }
        return out
    }
}
