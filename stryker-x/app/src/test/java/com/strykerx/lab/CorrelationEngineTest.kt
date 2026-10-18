package com.strykerx.lab

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.scanner.web.CorrelationEngine
import com.strykerx.lab.scanner.web.WebFinding
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CorrelationEngineTest {

    private fun f(code: String, sev: Severity = Severity.MEDIUM,
                  v: VerificationStatus = VerificationStatus.POTENTIAL) = WebFinding(
        code = code, title = code, affected = "x", detectionMethod = "t", evidence = "e",
        severity = sev, confidence = Confidence.MEDIUM, verification = v,
        reproduction = "r", remediation = "f"
    )

    @Test
    fun empty_findings_yield_no_insights() {
        assertTrue(CorrelationEngine.correlate(emptyList()).isEmpty())
    }

    @Test
    fun xss_plus_missing_csp_produces_elevated_insight() {
        val insights = CorrelationEngine.correlate(
            listOf(f("xss-q"), f("hdr-missing-content-security-policy"))
        )
        assertTrue(insights.any { it.code == "insight-xss-no-csp" && it.severity == Severity.HIGH })
    }

    @Test
    fun unrelated_findings_do_not_trigger_insights() {
        val insights = CorrelationEngine.correlate(listOf(f("waf-detected"), f("recon-dns")))
        assertFalse(insights.any { it.code == "insight-xss-no-csp" })
    }

    @Test
    fun two_confirmed_high_exposures_form_a_cluster() {
        val insights = CorrelationEngine.correlate(
            listOf(
                f("exposure-/.env", Severity.HIGH, VerificationStatus.CONFIRMED),
                f("exposure-/backup.sql", Severity.HIGH, VerificationStatus.CONFIRMED)
            )
        )
        assertTrue(insights.any { it.code == "insight-leak-cluster" })
    }

    @Test
    fun single_exposure_is_not_a_cluster() {
        val insights = CorrelationEngine.correlate(
            listOf(f("exposure-/.env", Severity.HIGH, VerificationStatus.CONFIRMED))
        )
        assertFalse(insights.any { it.code == "insight-leak-cluster" })
    }
}
