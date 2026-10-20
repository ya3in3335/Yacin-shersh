package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * A Nikto-like web signature scanner: our own curated database of known dangerous
 * files, backups, VCS/CI metadata, config and secret files. Non-destructive GET
 * probes, scope-locked via SafeHttp, each guarded against the SPA catch-all
 * baseline. A hit is only reported when the response is 200, differs from the
 * catch-all, and (where given) contains a confirming marker.
 */
class NiktoSignatureCheck : WebCheck {
    override val id = "nikto-signatures"
    override val displayName = "Known Dangerous Files"

    private data class Sig(val path: String, val label: String, val severity: Severity, val mustContain: String? = null)

    private val signatures = listOf(
        Sig("/phpinfo.php", "phpinfo() exposed", Severity.HIGH, "phpinfo()"),
        Sig("/info.php", "phpinfo() exposed", Severity.HIGH, "phpinfo()"),
        Sig("/test.php", "Test script exposed", Severity.LOW),
        Sig("/.htaccess", "Apache .htaccess readable", Severity.MEDIUM),
        Sig("/.htpasswd", "Apache .htpasswd readable (password hashes)", Severity.HIGH, ":"),
        Sig("/web.config", "ASP.NET web.config readable", Severity.HIGH, "<configuration"),
        Sig("/WEB-INF/web.xml", "Java web.xml readable", Severity.HIGH, "<web-app"),
        Sig("/crossdomain.xml", "Flash cross-domain policy", Severity.LOW, "cross-domain"),
        Sig("/clientaccesspolicy.xml", "Silverlight access policy", Severity.LOW),
        Sig("/.DS_Store", "macOS .DS_Store (directory metadata)", Severity.LOW),
        Sig("/.svn/entries", "Subversion metadata exposed", Severity.HIGH),
        Sig("/.hg/requires", "Mercurial metadata exposed", Severity.MEDIUM),
        Sig("/composer.json", "Composer manifest (dependency list)", Severity.LOW, "require"),
        Sig("/composer.lock", "Composer lockfile (exact versions)", Severity.LOW),
        Sig("/package.json", "Node package manifest", Severity.LOW),
        Sig("/yarn.lock", "Yarn lockfile", Severity.LOW),
        Sig("/Dockerfile", "Dockerfile exposed", Severity.MEDIUM, "FROM "),
        Sig("/docker-compose.yml", "docker-compose exposed", Severity.MEDIUM),
        Sig("/.travis.yml", "Travis CI config", Severity.LOW),
        Sig("/.gitlab-ci.yml", "GitLab CI config", Severity.LOW),
        Sig("/.circleci/config.yml", "CircleCI config", Severity.LOW),
        Sig("/wp-config.php.bak", "WordPress config backup (DB creds)", Severity.HIGH),
        Sig("/config.php.bak", "PHP config backup", Severity.HIGH),
        Sig("/backup.zip", "Backup archive exposed", Severity.HIGH),
        Sig("/backup.tar.gz", "Backup archive exposed", Severity.HIGH),
        Sig("/backup.sql", "Database dump exposed", Severity.HIGH),
        Sig("/dump.sql", "Database dump exposed", Severity.HIGH),
        Sig("/db.sql", "Database dump exposed", Severity.HIGH),
        Sig("/config.json", "Config JSON exposed", Severity.MEDIUM),
        Sig("/secrets.json", "Secrets file exposed", Severity.HIGH),
        Sig("/.aws/credentials", "AWS credentials file", Severity.HIGH),
        Sig("/id_rsa", "SSH private key exposed", Severity.HIGH, "PRIVATE KEY"),
        Sig("/.bash_history", "Shell history exposed", Severity.MEDIUM),
        Sig("/elmah.axd", "ELMAH error log handler", Severity.HIGH, "Error Log"),
        Sig("/trace.axd", "ASP.NET trace viewer", Severity.HIGH, "Application Trace"),
        Sig("/server-info", "Apache mod_info exposed", Severity.MEDIUM, "Apache Server Information")
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()

        val out = mutableListOf<WebFinding>()
        for (sig in signatures) {
            if (out.size >= 25) break
            val resp = http.get(baseUrl + sig.path) ?: continue
            if (resp.code != 200) continue
            if (ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) continue
            val body = resp.body.take(20_000)
            if (sig.mustContain != null && !body.contains(sig.mustContain, true)) continue
            out += WebFinding(
                code = "nikto-${sig.path}",
                title = "${sig.label} (${sig.path})",
                affected = resp.finalUrl,
                detectionMethod = "Signature file probe (catch-all guarded)",
                evidence = "HTTP 200 at ${sig.path}" +
                    (sig.mustContain?.let { " containing '$it'" } ?: "") + ".",
                severity = sig.severity,
                confidence = if (sig.mustContain != null) Confidence.HIGH else Confidence.MEDIUM,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Fetch ${resp.finalUrl}.",
                remediation = "Remove or block public access to this file; it should never be web-reachable."
            )
        }
        return out
    }
}
