package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/**
 * Deep signature scanner over Cherlogons' own [WebSignatures] database. Supports
 * status / body-marker / header matching and CGI-directory expansion, with the
 * SPA catch-all baseline guard to suppress false positives. All GET, read-only,
 * scope-locked via SafeHttp. The database is original (clean-room), not copied
 * from any other scanner.
 */
class NiktoSignatureCheck : WebCheck {
    override val id = "deep-signatures"
    override val displayName = "Deep File & Endpoint Signatures"

    private val maxRequests = 180
    private val maxFindings = 50

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()

        val out = mutableListOf<WebFinding>()
        var requests = 0

        for (sig in WebSignatures.ALL) {
            if (out.size >= maxFindings || requests >= maxRequests) break
            val paths = if (sig.cgiDir) WebSignatures.CGI_DIRS.map { it + sig.path } else listOf(sig.path)
            for (path in paths) {
                if (out.size >= maxFindings || requests >= maxRequests) break
                requests++
                val resp = http.get(baseUrl + path) ?: continue
                if (!matches(sig.match, resp, baseline)) continue
                out += WebFinding(
                    code = "sig-${sig.cat.name.lowercase()}-$path",
                    title = "${sig.label} [${sig.cat.label}]",
                    affected = resp.finalUrl,
                    detectionMethod = "Signature probe (catch-all guarded)",
                    evidence = evidenceFor(sig.match, resp),
                    severity = sig.severity,
                    confidence = confidenceFor(sig.match),
                    verification = VerificationStatus.CONFIRMED,
                    reproduction = "Fetch ${resp.finalUrl} and check: ${describe(sig.match)}.",
                    remediation = remediationFor(sig.cat)
                )
                break // one hit per signature is enough
            }
        }
        return out
    }

    private fun matches(
        m: WebSignatures.Match, resp: com.strykerx.lab.core.network.HttpResult,
        baseline: ExposureCheck.PageSignature?
    ): Boolean = when (m) {
        is WebSignatures.Match.Code ->
            resp.code == m.code &&
                !(m.code == 200 && ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp)))
        is WebSignatures.Match.CodeAndBody ->
            resp.code == m.code &&
                !(m.code == 200 && ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) &&
                resp.body.take(40_000).contains(m.needle, ignoreCase = true)
        is WebSignatures.Match.Body ->
            resp.code == 200 &&
                !ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp)) &&
                resp.body.take(40_000).contains(m.needle, ignoreCase = true)
        is WebSignatures.Match.Header ->
            resp.header(m.name)?.contains(m.needle, ignoreCase = true) == true
    }

    private fun confidenceFor(m: WebSignatures.Match): Confidence = when (m) {
        is WebSignatures.Match.Code -> Confidence.MEDIUM
        else -> Confidence.HIGH
    }

    private fun evidenceFor(m: WebSignatures.Match, resp: com.strykerx.lab.core.network.HttpResult): String = when (m) {
        is WebSignatures.Match.Code -> "HTTP ${resp.code} at this path."
        is WebSignatures.Match.CodeAndBody -> "HTTP ${resp.code} and body contains '${m.needle}'."
        is WebSignatures.Match.Body -> "Body contains '${m.needle}'."
        is WebSignatures.Match.Header -> "Header '${m.name}' contains '${m.needle}'."
    }

    private fun describe(m: WebSignatures.Match): String = when (m) {
        is WebSignatures.Match.Code -> "status == ${m.code}"
        is WebSignatures.Match.CodeAndBody -> "status == ${m.code} and body contains '${m.needle}'"
        is WebSignatures.Match.Body -> "body contains '${m.needle}'"
        is WebSignatures.Match.Header -> "header '${m.name}' contains '${m.needle}'"
    }

    private fun remediationFor(cat: WebSignatures.Cat): String = when (cat) {
        WebSignatures.Cat.SECRET -> "Remove this file from the web root and rotate any exposed credential immediately."
        WebSignatures.Cat.BACKUP -> "Delete web-reachable backups/dumps; store them off the web root with access control."
        WebSignatures.Cat.VCS -> "Block access to VCS metadata (deny .git/.svn/.hg) — it can reconstruct source."
        WebSignatures.Cat.CI_CONFIG -> "Do not deploy CI/dependency manifests to production web roots."
        WebSignatures.Cat.INFO -> "Disable this information-disclosure surface in production."
        WebSignatures.Cat.DEBUG -> "Disable/secure debug and management endpoints in production (auth + network restriction)."
        WebSignatures.Cat.CGI -> "Remove legacy/unneeded CGI scripts; patch and restrict those required."
        WebSignatures.Cat.ADMIN -> "Restrict admin consoles to trusted networks/VPN and require strong authentication."
        WebSignatures.Cat.DEFAULT -> "Remove default/example content shipped with the server/framework."
    }
}
