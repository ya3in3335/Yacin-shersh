package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext
import com.yacin.vulnscan.scanner.Severity

class ExposureCheck : Check {
    override val id = "exposure"

    private data class Probe(val sev: Severity, val title: String, val signatures: List<String>)

    private val paths = mapOf(
        "/.git/HEAD" to Probe(Severity.HIGH, "Exposed .git repository", listOf("ref:", "refs/heads")),
        "/.env" to Probe(Severity.HIGH, "Exposed .env file", listOf("APP_", "DB_", "SECRET", "KEY=")),
        "/.svn/entries" to Probe(Severity.MEDIUM, "Exposed .svn metadata", listOf("svn", "dir")),
        "/wp-config.php.bak" to Probe(Severity.HIGH, "Exposed WordPress config backup", listOf("DB_PASSWORD", "DB_USER")),
        "/phpinfo.php" to Probe(Severity.MEDIUM, "Exposed phpinfo()", listOf("PHP Version", "phpinfo")),
        "/server-status" to Probe(Severity.MEDIUM, "Exposed Apache server-status", listOf("Apache Server Status")),
        "/robots.txt" to Probe(Severity.INFO, "robots.txt present", listOf("Disallow", "User-agent"))
    )

    override fun run(ctx: ScanContext): List<Finding> {
        val out = mutableListOf<Finding>()
        for ((path, probe) in paths) {
            val url = ctx.baseUrl + path
            val resp = ctx.execute(url) ?: continue
            resp.use {
                if (it.code != 200) return@use
                val body = it.body?.string()?.take(4096) ?: ""
                if (probe.signatures.none { sig -> body.contains(sig) }) return@use
                out += Finding(
                    id, probe.title, probe.sev, url,
                    evidence = if (path == "/robots.txt") body.take(300) else "",
                    remediation = "Remove the file from the web root or block access."
                )
            }
        }
        // Directory listing
        ctx.execute(ctx.baseUrl + "/")?.use {
            val body = it.body?.string() ?: ""
            if (it.code == 200 && body.contains("<title>Index of")) {
                out += Finding(
                    id, "Directory listing enabled", Severity.MEDIUM, ctx.baseUrl + "/",
                    remediation = "Disable autoindex / directory browsing."
                )
            }
        }
        return out
    }
}
