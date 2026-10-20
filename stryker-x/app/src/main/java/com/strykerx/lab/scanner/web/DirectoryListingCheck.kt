package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Detects open directory listings ("Index of /") on common paths. */
class DirectoryListingCheck : WebCheck {
    override val id = "dir-listing"
    override val displayName = "Directory Listing"

    private val paths = listOf("/", "/uploads/", "/images/", "/img/", "/assets/", "/files/", "/backup/", "/static/", "/js/", "/css/")
    private val listingRx = Regex("(?i)<title>\\s*Index of /|<h1>\\s*Index of /|Directory listing for ")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()
        val out = mutableListOf<WebFinding>()
        for (path in paths) {
            val resp = http.get(baseUrl + path) ?: continue
            if (resp.code != 200) continue
            if (ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) continue
            if (!listingRx.containsMatchIn(resp.body.take(20_000))) continue
            out += WebFinding(
                code = "dir-listing-$path",
                title = "Open directory listing at $path",
                affected = resp.finalUrl,
                detectionMethod = "Directory index detection",
                evidence = "Response contains an auto-generated directory index ('Index of /').",
                severity = Severity.MEDIUM,
                confidence = Confidence.HIGH,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Fetch ${resp.finalUrl} in a browser.",
                remediation = "Disable automatic directory indexing (e.g. 'Options -Indexes' / autoindex off)."
            )
            if (out.size >= 5) break
        }
        return out
    }
}
