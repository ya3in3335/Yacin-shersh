package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.URLEncoder
import kotlin.math.abs

/**
 * Opt-in, non-destructive SQL-injection and reflected-XSS detection. Only query
 * parameters already present in the target URL are tested. Techniques:
 *   - error-based  : a single quote, matched against DBMS error signatures
 *   - boolean blind: differential of `AND 1=1` vs `AND 1=2` response bodies
 *   - reflected XSS: a benign unique marker reflected unencoded
 * No data is extracted and no time-based (sleep) payloads are sent — detection
 * only. Findings are POTENTIAL and require manual confirmation.
 */
class InjectionCheck : WebCheck {
    override val id = "injection"
    override val displayName = "Injection (opt-in)"

    private val marker = "chx9z7q"
    private val xssPayload = "'\"><$marker>"

    // Error signatures across many database engines (error-based detection).
    private val sqlErrors = listOf(
        "MySQL" to Regex("SQL syntax.*MySQL|Warning.*\\bmysqli?_|valid MySQL result|MySqlClient\\.", RegexOption.IGNORE_CASE),
        "PostgreSQL" to Regex("PostgreSQL.*ERROR|pg_query\\(\\)|pg_exec\\(\\)|PSQLException", RegexOption.IGNORE_CASE),
        "MSSQL" to Regex("Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|\\bSQLServer JDBC Driver|System\\.Data\\.SqlClient\\.SqlException", RegexOption.IGNORE_CASE),
        "Oracle" to Regex("ORA-\\d{5}|Oracle error|Oracle.*Driver|quoted string not properly terminated", RegexOption.IGNORE_CASE),
        "SQLite" to Regex("SQLite/JDBCDriver|SQLite3::|\\bsqlite3\\.OperationalError|\\[SQLITE_ERROR\\]", RegexOption.IGNORE_CASE),
        "DB2" to Regex("CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(", RegexOption.IGNORE_CASE),
        "Sybase" to Regex("Sybase message|Warning.*sybase|Sybase.*Server message", RegexOption.IGNORE_CASE),
        "Generic" to Regex("SQL syntax.*error|syntax error at or near|unterminated quoted string|quoted string not properly terminated", RegexOption.IGNORE_CASE)
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val qIndex = baseUrl.indexOf('?')
        if (qIndex < 0) return emptyList()
        val base = baseUrl.substring(0, qIndex)
        val params = baseUrl.substring(qIndex + 1).split("&").mapNotNull {
            val i = it.indexOf('='); if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
        }
        if (params.isEmpty()) return emptyList()

        val baselineLen = http.get(baseUrl)?.body?.length
        val out = mutableListOf<WebFinding>()

        for ((key, original) in params) {
            // --- Error-based SQLi ---
            buildUrl(base, params, key, "$original'")?.let { url ->
                http.get(url)?.let { r ->
                    sqlErrors.firstOrNull { it.second.containsMatchIn(r.body) }?.let { (engine, pat) ->
                        out += finding(
                            "sqli-error-$key", "Possible SQL injection in '$key' ($engine error)", url,
                            "Error-based probe (single quote)", "DB error ($engine): ${pat.pattern.take(60)}",
                            Severity.HIGH, Confidence.MEDIUM,
                            "Set '$key' to \"$original'\" and observe a $engine error in the response.",
                            "Use parameterized queries / prepared statements."
                        )
                    }
                }
            }

            // --- Boolean-based blind SQLi (differential) ---
            if (baselineLen != null) {
                val trueLen = fetchLen(http, buildUrl(base, params, key, "$original AND 1=1"))
                val falseLen = fetchLen(http, buildUrl(base, params, key, "$original AND 1=2"))
                if (trueLen != null && falseLen != null &&
                    isBlindSignal(baselineLen, trueLen, falseLen)
                ) {
                    out += finding(
                        "sqli-blind-$key", "Possible boolean-based blind SQL injection in '$key'", baseUrl,
                        "Boolean differential (AND 1=1 vs AND 1=2)",
                        "true-page≈baseline ($trueLen vs $baselineLen), false-page differs ($falseLen)",
                        Severity.HIGH, Confidence.LOW,
                        "Compare responses for '$key' with 'AND 1=1' vs 'AND 1=2'; a consistent difference indicates blind SQLi.",
                        "Use parameterized queries; do not build SQL from user input."
                    )
                }
            }

            // --- Reflected XSS ---
            buildUrl(base, params, key, xssPayload)?.let { url ->
                http.get(url)?.let { r ->
                    if (r.body.contains("<$marker>")) {
                        out += finding(
                            "xss-$key", "Reflected input without encoding in '$key' (possible XSS)", url,
                            "Reflected unique-marker probe", "Marker <$marker> reflected unencoded",
                            Severity.HIGH, Confidence.MEDIUM,
                            "Inject the marker into '$key' and confirm it is reflected unencoded in HTML context.",
                            "Apply context-aware output encoding and a strict CSP."
                        )
                    }
                }
            }
        }
        return out
    }

    private fun fetchLen(http: SafeHttp, url: String?): Int? =
        url?.let { http.get(it)?.body?.length }

    private fun buildUrl(
        base: String, params: List<Pair<String, String>>, key: String, value: String
    ): String? = runCatching {
        val q = params.joinToString("&") { (k, v) ->
            "${enc(k)}=${enc(if (k == key) value else v)}"
        }
        "$base?$q"
    }.getOrNull()

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    @Suppress("LongParameterList")
    private fun finding(
        code: String, title: String, affected: String, method: String, evidence: String,
        sev: Severity, conf: Confidence, repro: String, fix: String
    ) = WebFinding(
        code = code, title = title, affected = affected, detectionMethod = method,
        evidence = evidence, severity = sev, confidence = conf,
        verification = VerificationStatus.POTENTIAL, reproduction = repro, remediation = fix
    )

    companion object {
        /**
         * Boolean-based blind signal: the `AND 1=1` page stays close to the
         * baseline while the `AND 1=2` page differs clearly (and differs from the
         * true page). Pure and unit-tested.
         */
        fun isBlindSignal(base: Int, t: Int, f: Int): Boolean {
            if (base == 0) return false
            val trueClose = abs(t - base) <= base * 0.02
            val falseDiffers = abs(f - base) >= base * 0.05
            val tfDiffer = abs(t - f) >= base * 0.05
            return trueClose && falseDiffers && tfDiffer
        }
    }
}
