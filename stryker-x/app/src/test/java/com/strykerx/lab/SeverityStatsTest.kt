package com.strykerx.lab

import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.SeverityStats
import com.strykerx.lab.core.common.VerificationStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class SeverityStatsTest {

    @Test
    fun reduces_severity_list_correctly() {
        val stats = SeverityStats.of(
            listOf(
                Severity.CRITICAL, Severity.CRITICAL,
                Severity.HIGH,
                Severity.LOW, Severity.LOW, Severity.LOW,
                Severity.INFO
            )
        )
        assertEquals(2, stats.critical)
        assertEquals(1, stats.high)
        assertEquals(0, stats.medium)
        assertEquals(3, stats.low)
        assertEquals(1, stats.info)
        assertEquals(7, stats.total)
    }

    @Test
    fun empty_list_is_all_zero() {
        val stats = SeverityStats.of(emptyList())
        assertEquals(0, stats.total)
    }

    @Test
    fun severity_parsing_is_case_insensitive_with_fallback() {
        assertEquals(Severity.HIGH, Severity.from("high"))
        assertEquals(Severity.CRITICAL, Severity.from("CRITICAL"))
        assertEquals(Severity.INFO, Severity.from(null))
        assertEquals(Severity.INFO, Severity.from("bogus"))
    }

    @Test
    fun verification_defaults_to_unverified_never_confirmed() {
        assertEquals(VerificationStatus.UNVERIFIED, VerificationStatus.from(null))
        assertEquals(VerificationStatus.UNVERIFIED, VerificationStatus.from("unknown-value"))
        assertEquals(VerificationStatus.CONFIRMED, VerificationStatus.from("confirmed"))
    }
}
