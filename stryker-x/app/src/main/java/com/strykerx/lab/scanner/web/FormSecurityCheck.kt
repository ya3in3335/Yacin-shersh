package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Passive analysis of HTML forms: insecure submission, missing CSRF token, password handling. */
class FormSecurityCheck : WebCheck {
    override val id = "form-security"
    override val displayName = "Form Security"

    private val formRx = Regex("(?is)<form\\b.*?</form>")
    private val actionRx = Regex("""action\s*=\s*["']([^"']*)["']""", RegexOption.IGNORE_CASE)
    private val csrfRx = Regex("(?i)(csrf|xsrf|authenticity_token|__requestverificationtoken|_token)")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val resp = http.get(baseUrl) ?: return emptyList()
        val body = resp.body.take(400_000)
        val out = mutableListOf<WebFinding>()

        val forms = formRx.findAll(body).map { it.value }.take(25).toList()
        var insecureAction = 0
        var passwordNoCsrf = 0
        for (form in forms) {
            val hasPassword = form.contains("type=\"password\"", true) || form.contains("type='password'", true)
            val action = actionRx.find(form)?.groupValues?.getOrNull(1).orEmpty()
            if (action.startsWith("http://", true)) insecureAction++
            if (hasPassword && !csrfRx.containsMatchIn(form)) passwordNoCsrf++
        }

        if (insecureAction > 0) {
            out += WebFinding(
                code = "form-insecure-action",
                title = "$insecureAction form(s) submit over cleartext http://",
                affected = resp.finalUrl,
                detectionMethod = "Passive HTML form analysis",
                evidence = "Form action targets an http:// URL — submitted data (possibly credentials) can be intercepted.",
                severity = Severity.HIGH,
                confidence = Confidence.HIGH,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Fetch ${resp.finalUrl} and inspect <form action> attributes.",
                remediation = "Submit all forms over HTTPS."
            )
        }
        if (passwordNoCsrf > 0) {
            out += WebFinding(
                code = "form-no-csrf",
                title = "$passwordNoCsrf password form(s) without a visible CSRF token",
                affected = resp.finalUrl,
                detectionMethod = "Passive HTML form analysis",
                evidence = "A form containing a password field has no recognizable anti-CSRF token field.",
                severity = Severity.LOW,
                confidence = Confidence.LOW,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Fetch ${resp.finalUrl} and inspect the login form for a CSRF token.",
                remediation = "Include a per-session anti-CSRF token (or SameSite cookies) and verify it server-side."
            )
        }
        return out
    }
}
