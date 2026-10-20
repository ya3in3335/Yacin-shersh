package com.strykerx.lab

import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.feature.reports.ReportBuilder
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportBuilderTest {

    private fun finding(sev: Severity, title: String) = FindingEntity(
        id = title, sessionId = "s1", findingCode = "code-$title", title = title,
        target = "https://example.com", affected = "https://example.com",
        detectionMethod = "test", evidence = "ev", severity = sev.name,
        confidence = "HIGH", verificationStatus = VerificationStatus.POTENTIAL.name,
        reproduction = "repro", remediation = "fix", dedupeKey = "code-$title", createdAt = 0
    )

    @Test
    fun markdown_contains_summary_and_findings() {
        val md = ReportBuilder.markdown(
            "https://example.com",
            listOf(finding(Severity.HIGH, "A"), finding(Severity.LOW, "B"))
        )
        assertTrue(md.contains("Executive Summary"))
        assertTrue(md.contains("https://example.com"))
        assertTrue(md.contains("A"))
        assertTrue(md.contains("B"))
    }

    @Test
    fun markdown_handles_empty_findings() {
        val md = ReportBuilder.markdown("https://example.com", emptyList())
        assertTrue(md.contains("No findings."))
    }

    @Test
    fun ai_prompt_wraps_the_report() {
        val prompt = ReportBuilder.aiPrompt("https://example.com", listOf(finding(Severity.MEDIUM, "X")))
        assertTrue(prompt.contains("RAW FINDINGS"))
        assertTrue(prompt.contains("cybersecurity expert"))
    }

    @Test
    fun hackerone_uses_highest_severity_first() {
        val report = ReportBuilder.hackerOne(
            "https://example.com",
            listOf(finding(Severity.LOW, "low-one"), finding(Severity.CRITICAL, "crit-one"))
        )
        assertTrue(report.contains("crit-one"))
    }
}
