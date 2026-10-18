package com.strykerx.lab

import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.SecurityScore
import com.strykerx.lab.core.common.VerificationStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityScoreTest {

    @Test
    fun clean_scan_scores_full_positive() {
        val r = SecurityScore.compute(emptyList())
        assertEquals(100, r.percent)
        assertEquals("score_excellent", r.gradeKey)
    }

    @Test
    fun informational_findings_do_not_reduce_the_score() {
        val r = SecurityScore.compute(
            listOf(
                Severity.INFO to VerificationStatus.INFORMATIONAL,
                Severity.MEDIUM to VerificationStatus.INFORMATIONAL
            )
        )
        assertEquals(100, r.percent)
    }

    @Test
    fun false_positives_are_ignored() {
        val r = SecurityScore.compute(
            listOf(Severity.HIGH to VerificationStatus.FALSE_POSITIVE)
        )
        assertEquals(100, r.percent)
    }

    @Test
    fun confirmed_high_findings_push_score_down() {
        // two confirmed HIGH => 100 - 2*28 = 44 -> "good"
        val r = SecurityScore.compute(
            listOf(
                Severity.HIGH to VerificationStatus.CONFIRMED,
                Severity.HIGH to VerificationStatus.CONFIRMED
            )
        )
        assertEquals(44, r.percent)
        assertEquals("score_good", r.gradeKey)
    }

    @Test
    fun severe_sites_go_below_zero_and_clamp() {
        val many = List(10) { Severity.CRITICAL to VerificationStatus.CONFIRMED }
        val r = SecurityScore.compute(many)
        assertTrue(r.percent < 0)
        assertTrue(r.percent >= -100)
        assertEquals("score_atrisk", r.gradeKey)
    }

    @Test
    fun potential_counts_less_than_confirmed() {
        val confirmed = SecurityScore.compute(listOf(Severity.MEDIUM to VerificationStatus.CONFIRMED)).percent
        val potential = SecurityScore.compute(listOf(Severity.MEDIUM to VerificationStatus.POTENTIAL)).percent
        assertTrue(potential > confirmed)
    }
}
