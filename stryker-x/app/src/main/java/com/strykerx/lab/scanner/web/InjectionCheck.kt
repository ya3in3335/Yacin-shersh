package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.URLEncoder

/**
 * Opt-in, low-impact reflected-XSS and error-based SQLi probing. Only query
 * parameters already present in the target URL are tested, using a benign
 * unique marker and a single quote. No destructive payloads are ever sent.
 * Gated behind the operator's explicit "active tests" authorization.
 */
class InjectionCheck : WebCheck {
    override val id = "injection"
    override val displayName = "Injection (opt-in)"

    private val marker = "chx9z7q"
    private val xssPayload = "'\"><$marker>"

    private val sqlErrors = listOf(
        Regex("SQL syntax.*MySQL", RegexOption.IGNORE_CASE),
        Regex("Warning.*\\bmysqli?_", RegexOption.IGNORE_CASE),
        Regex("PostgreSQL.*ERROR", RegexOption.IGNORE_CASE),
        Regex("ORA-\\d{5}", RegexOption.IGNORE_CASE),
        Regex("Microsoft OLE DB Provider for SQL Server", RegexOption.IGNORE_CASE),
        Regex("SQLite/JDBCDriver|SQLite3::", RegexOption.IGNORE_CASE),
        Regex("Unclosed quotation mark after the character string", RegexOption.IGNORE_CASE)
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val qIndex = baseUrl.indexOf('?')
        if (qIndex < 0) return emptyList()
        val base = baseUrl.substring(0, qIndex)
        val query = baseUrl.substring(qIndex + 1)
        val params = query.split("&").mapNotNull {
            val i = it.indexOf('='); if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
        }
        if (params.isEmpty()) return emptyList()

        val out = mutableListOf<WebFinding>()
        for ((key, _) in params) {
            // Error-based SQLi: a single quote.
            buildUrl(base, params, key, "1'")?.let { url ->
                http.get(url)?.let { r ->
                    sqlErrors.firstOrNull { it.containsMatchIn(r.body) }?.let { pat ->
                        out += WebFinding(
                            code = "sqli-$key",
                            title = "Possible SQL injection in parameter '$key'",
                            affected = url,
                            detectionMethod = "Error-based probe (single quote)",
                            evidence = "DB error signature: ${pat.pattern}",
                            severity = Severity.HIGH,
                            confidence = Confidence.MEDIUM,
                            verification = VerificationStatus.POTENTIAL,
                            reproduction = "Set '$key' to \"1'\" and observe a database error in the response.",
                            remediation = "Use parameterized queries / prepared statements."
                        )
                    }
                }
            }
            // Reflected XSS: unique marker.
            buildUrl(base, params, key, xssPayload)?.let { url ->
                http.get(url)?.let { r ->
                    if (r.body.contains("<$marker>")) {
                        out += WebFinding(
                            code = "xss-$key",
                            title = "Reflected input without encoding in '$key' (possible XSS)",
                            affected = url,
                            detectionMethod = "Reflected unique-marker probe",
                            evidence = "Marker <$marker> reflected unencoded",
                            severity = Severity.HIGH,
                            confidence = Confidence.MEDIUM,
                            verification = VerificationStatus.POTENTIAL,
                            reproduction = "Inject the marker into '$key' and confirm it is reflected unencoded in HTML context.",
                            remediation = "Apply context-aware output encoding and a strict CSP."
                        )
                    }
                }
            }
        }
        return out
    }

    private fun buildUrl(
        base: String, params: List<Pair<String, String>>, key: String, value: String
    ): String? = runCatching {
        val q = params.joinToString("&") { (k, v) ->
            val newV = if (k == key) value else v
            "${enc(k)}=${enc(newV)}"
        }
        "$base?$q"
    }.getOrNull()

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}
