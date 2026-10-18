package com.strykerx.lab.core.common

import com.strykerx.lab.core.database.FindingEntity
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Computes a site "security strength" score from scan findings.
 *
 * The scale is signed: +100% = no real weaknesses observed (strong), 0% = even,
 * negative = the site is in a weak / at-risk state. A clean scan scores high
 * positive; confirmed high-severity issues push it toward (and below) zero.
 *
 * It is a heuristic derived from THIS scan's observations — not an absolute
 * guarantee — and is intentionally pure so it can be unit-tested.
 */
object SecurityScore {

    data class Result(val percent: Int, val gradeKey: String)

    private fun severityWeight(sev: Severity): Double = when (sev) {
        Severity.CRITICAL -> 45.0
        Severity.HIGH -> 28.0
        Severity.MEDIUM -> 14.0
        Severity.LOW -> 6.0
        Severity.INFO -> 0.0
    }

    // How much a finding counts, by how well it is established.
    private fun verificationFactor(status: VerificationStatus): Double = when (status) {
        VerificationStatus.CONFIRMED -> 1.0
        VerificationStatus.POTENTIAL -> 0.6
        VerificationStatus.UNVERIFIED -> 0.4
        VerificationStatus.INFORMATIONAL -> 0.0
        VerificationStatus.FALSE_POSITIVE -> 0.0
    }

    /** Core pure computation over (severity, verification) pairs. */
    fun compute(items: List<Pair<Severity, VerificationStatus>>): Result {
        val penalty = items.sumOf { (sev, status) ->
            severityWeight(sev) * verificationFactor(status)
        }
        val percent = max(-100.0, min(100.0, 100.0 - penalty)).roundToInt()
        return Result(percent, gradeKeyFor(percent))
    }

    /** Convenience overload for persisted findings. */
    fun fromFindings(findings: List<FindingEntity>): Result =
        compute(findings.map { Severity.from(it.severity) to VerificationStatus.from(it.verificationStatus) })

    private fun gradeKeyFor(percent: Int): String = when {
        percent >= 80 -> "score_excellent"
        percent >= 50 -> "score_verygood"
        percent >= 20 -> "score_good"
        percent >= 0 -> "score_needswork"
        else -> "score_atrisk"
    }
}
