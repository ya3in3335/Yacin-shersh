package com.yacin.vulnscan.scanner

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Builds organized, shareable reports from scan findings. */
object ReportBuilder {

    private fun now(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())

    private fun summary(findings: List<Finding>): Map<Severity, Int> =
        Severity.values().associateWith { sev -> findings.count { it.severity == sev } }

    /** A clean Markdown report, grouped by severity. */
    fun markdown(target: String, findings: List<Finding>): String {
        val sb = StringBuilder()
        val counts = summary(findings)
        sb.appendLine("# تقرير فحص الثغرات — VulnScan")
        sb.appendLine()
        sb.appendLine("- **الهدف:** $target")
        sb.appendLine("- **التاريخ:** ${now()}")
        sb.appendLine("- **إجمالي النتائج:** ${findings.size}")
        sb.appendLine()
        sb.appendLine("## الملخّص التنفيذي")
        sb.appendLine()
        sb.appendLine("| الخطورة | العدد |")
        sb.appendLine("|---|---|")
        for (sev in Severity.values()) {
            sb.appendLine("| ${sev.label} | ${counts[sev]} |")
        }
        sb.appendLine()

        if (findings.isEmpty()) {
            sb.appendLine("لم يتم العثور على نتائج.")
            return sb.toString()
        }

        for (sev in Severity.values()) {
            val group = findings.filter { it.severity == sev }
            if (group.isEmpty()) continue
            sb.appendLine("## ${sev.label} (${group.size})")
            sb.appendLine()
            group.forEachIndexed { i, f ->
                sb.appendLine("### ${i + 1}. ${f.title}")
                sb.appendLine("- **الاختبار:** ${f.check}")
                sb.appendLine("- **الموقع:** ${f.target}")
                if (f.detail.isNotEmpty()) sb.appendLine("- **التفاصيل:** ${f.detail}")
                if (f.evidence.isNotEmpty()) sb.appendLine("- **الدليل:** `${f.evidence}`")
                if (f.remediation.isNotEmpty()) sb.appendLine("- **الإصلاح المقترح:** ${f.remediation}")
                sb.appendLine()
            }
        }
        sb.appendLine("---")
        sb.appendLine("_تم إنشاؤه بواسطة VulnScan — للفحص المُصرّح به فقط._")
        return sb.toString()
    }

    /**
     * Wraps the report in a prompt so an on-device AI app turns it into a
     * polished organizational report. Shared via the Android sharesheet.
     */
    fun aiPrompt(target: String, findings: List<Finding>): String {
        val report = markdown(target, findings)
        return buildString {
            appendLine("أنت خبير أمن سيبراني. حوّل نتائج الفحص التالية إلى تقرير أمني")
            appendLine("احترافي جاهز لتسليمه إلى المنظمة، ويتضمّن:")
            appendLine("1) ملخّص تنفيذي موجّه للإدارة.")
            appendLine("2) جدول بالثغرات مرتّبة حسب الخطورة مع تقييم الأثر.")
            appendLine("3) خطوات المعالجة (Remediation) وأولوياتها.")
            appendLine("4) توصيات عامة لتحسين الوضع الأمني.")
            appendLine("اكتب التقرير بالعربية بأسلوب رسمي ومنظّم.")
            appendLine()
            appendLine("=== نتائج الفحص الخام ===")
            append(report)
        }
    }
}
