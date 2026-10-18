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
        // Source control / metadata
        "/.git/HEAD" to Probe(Severity.HIGH, "Exposed .git repository", listOf("ref:", "refs/heads")),
        "/.git/config" to Probe(Severity.HIGH, "Exposed .git config", listOf("[core]", "remote \"")),
        "/.svn/entries" to Probe(Severity.MEDIUM, "Exposed .svn metadata", listOf("svn", "dir")),
        "/.hg/requires" to Probe(Severity.MEDIUM, "Exposed Mercurial metadata", listOf("revlog", "store")),
        // Secrets / environment
        "/.env" to Probe(Severity.HIGH, "Exposed .env file", listOf("APP_", "DB_", "SECRET", "KEY=")),
        "/.env.local" to Probe(Severity.HIGH, "Exposed .env.local file", listOf("APP_", "DB_", "SECRET", "KEY=")),
        "/.env.production" to Probe(Severity.HIGH, "Exposed .env.production file", listOf("APP_", "DB_", "SECRET")),
        "/config.json" to Probe(Severity.MEDIUM, "Exposed config.json", listOf("password", "secret", "apiKey", "token")),
        "/credentials.json" to Probe(Severity.HIGH, "Exposed credentials.json", listOf("private_key", "client_email", "password")),
        "/.aws/credentials" to Probe(Severity.HIGH, "Exposed AWS credentials", listOf("aws_access_key_id", "aws_secret_access_key")),
        // Config backups
        "/wp-config.php.bak" to Probe(Severity.HIGH, "Exposed WordPress config backup", listOf("DB_PASSWORD", "DB_USER")),
        "/config.php.bak" to Probe(Severity.HIGH, "Exposed config.php backup", listOf("<?php", "password", "db")),
        "/web.config.bak" to Probe(Severity.HIGH, "Exposed web.config backup", listOf("<configuration", "connectionString")),
        "/.htpasswd" to Probe(Severity.HIGH, "Exposed .htpasswd", listOf(":\$apr1\$", ":\$2y\$", ":{SHA}")),
        // Server / framework status & debug
        "/phpinfo.php" to Probe(Severity.MEDIUM, "Exposed phpinfo()", listOf("PHP Version", "phpinfo")),
        "/server-status" to Probe(Severity.MEDIUM, "Exposed Apache server-status", listOf("Apache Server Status")),
        "/actuator" to Probe(Severity.MEDIUM, "Exposed Spring Boot actuator", listOf("\"_links\"", "\"health\"", "\"self\"")),
        "/actuator/env" to Probe(Severity.HIGH, "Exposed actuator env", listOf("\"propertySources\"", "systemProperties")),
        "/actuator/health" to Probe(Severity.LOW, "Exposed actuator health", listOf("\"status\"")),
        "/_profiler" to Probe(Severity.MEDIUM, "Exposed Symfony profiler", listOf("Symfony Profiler", "sf-toolbar")),
        // API docs / specs
        "/swagger.json" to Probe(Severity.LOW, "Exposed Swagger spec", listOf("\"swagger\"", "\"openapi\"", "\"paths\"")),
        "/openapi.json" to Probe(Severity.LOW, "Exposed OpenAPI spec", listOf("\"openapi\"", "\"paths\"")),
        "/swagger-ui.html" to Probe(Severity.LOW, "Exposed Swagger UI", listOf("Swagger UI", "swagger-ui")),
        "/graphql" to Probe(Severity.LOW, "GraphQL endpoint present", listOf("\"data\"", "\"errors\"", "GraphQL")),
        // Archives / dumps
        "/backup.zip" to Probe(Severity.MEDIUM, "Exposed backup archive", listOf("PK\u0003\u0004")),
        "/backup.sql" to Probe(Severity.HIGH, "Exposed SQL dump", listOf("CREATE TABLE", "INSERT INTO", "DROP TABLE")),
        "/database.sql" to Probe(Severity.HIGH, "Exposed SQL dump", listOf("CREATE TABLE", "INSERT INTO")),
        "/dump.sql" to Probe(Severity.HIGH, "Exposed SQL dump", listOf("CREATE TABLE", "INSERT INTO")),
        // CI / container / misc
        "/docker-compose.yml" to Probe(Severity.MEDIUM, "Exposed docker-compose.yml", listOf("services:", "image:", "ports:")),
        "/.gitlab-ci.yml" to Probe(Severity.LOW, "Exposed GitLab CI config", listOf("stages:", "script:")),
        "/.DS_Store" to Probe(Severity.LOW, "Exposed .DS_Store", listOf("Bud1")),
        // Informational / policy
        "/.well-known/security.txt" to Probe(Severity.INFO, "security.txt present", listOf("Contact:", "Policy:")),
        "/security.txt" to Probe(Severity.INFO, "security.txt present", listOf("Contact:", "Policy:")),
        "/robots.txt" to Probe(Severity.INFO, "robots.txt present", listOf("Disallow", "User-agent")),
        "/sitemap.xml" to Probe(Severity.INFO, "sitemap.xml present", listOf("<urlset", "<sitemapindex", "<loc>")),
        "/crossdomain.xml" to Probe(Severity.LOW, "Flash crossdomain policy present", listOf("cross-domain-policy", "allow-access-from"))
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
