package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Engine-level finding, later mapped to a persisted FindingEntity. */
data class WebFinding(
    val code: String,
    val title: String,
    val affected: String,
    val detectionMethod: String,
    val evidence: String,
    val severity: Severity,
    val confidence: Confidence,
    val verification: VerificationStatus,
    val reproduction: String,
    val remediation: String
) {
    val dedupeKey: String get() = "$code|$affected"
}

/** A modular, non-destructive web check. Must not throw; return empty on failure. */
interface WebCheck {
    val id: String
    val displayName: String
    fun run(http: SafeHttp, baseUrl: String): List<WebFinding>
}
