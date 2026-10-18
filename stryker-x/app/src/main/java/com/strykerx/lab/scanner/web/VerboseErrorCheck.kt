package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * Detects verbose error pages / stack traces exposed to visitors — they leak
 * framework internals, file paths and sometimes queries. Read-only: it only
 * inspects the normal response body plus one benign malformed request.
 */
class VerboseErrorCheck : WebCheck {
    override val id = "verbose-errors"
    override val displayName = "Verbose Error Disclosure"

    private val signatures = listOf(
        "Java/Spring stack trace" to Regex("""\bat [\w.$]+\([\w.]+\.java:\d+\)"""),
        "Python traceback" to Regex("""Traceback \(most recent call last\):"""),
        "PHP error" to Regex("""(Fatal error|Warning|Notice):.*on line \d+|Stack trace:""", RegexOption.IGNORE_CASE),
        "ASP.NET error" to Regex("""Server Error in '.*' Application|System\.\w+Exception:"""),
        "Ruby error" to Regex("""\b(NoMethodError|RuntimeError)\b.*\.rb:\d+"""),
        "Node.js error" to Regex("""\bat .+\(.*\.js:\d+:\d+\)"""),
        "Django debug" to Regex("""You're seeing this error because you have DEBUG = True""")
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val out = mutableListOf<WebFinding>()
        // The normal page, plus one deliberately odd path that often triggers errors.
        val bodies = listOfNotNull(
            http.get(baseUrl)?.body,
            http.get("$baseUrl/%27%22%3E").takeIf { it != null }?.body
        )
        for (body in bodies) {
            signatures.firstOrNull { it.second.containsMatchIn(body) }?.let { (label, _) ->
                out += WebFinding(
                    code = "verbose-error",
                    title = "Verbose error / stack trace exposed ($label)",
                    affected = baseUrl,
                    detectionMethod = "Response body error-signature match",
                    evidence = "Matched $label pattern in a response",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.POTENTIAL,
                    reproduction = "Trigger an error (e.g. a malformed path/parameter) and observe a stack trace in the response.",
                    remediation = "Disable debug mode in production; return generic error pages and log details server-side."
                )
                return out // one is enough
            }
        }
        return out
    }
}
