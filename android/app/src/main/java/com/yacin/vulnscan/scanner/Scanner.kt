package com.yacin.vulnscan.scanner

import com.yacin.vulnscan.scanner.checks.Check
import com.yacin.vulnscan.scanner.checks.ExposureCheck
import com.yacin.vulnscan.scanner.checks.FingerprintCheck
import com.yacin.vulnscan.scanner.checks.HeaderCheck
import com.yacin.vulnscan.scanner.checks.PortCheck
import com.yacin.vulnscan.scanner.checks.TlsCheck

object Scanner {

    val allChecks: List<Check> = listOf(
        HeaderCheck(), TlsCheck(), ExposureCheck(), FingerprintCheck(), PortCheck()
    )

    fun normalizeUrl(raw: String): String {
        var v = raw.trim()
        if (!v.startsWith("http://") && !v.startsWith("https://")) v = "https://$v"
        return v.trimEnd('/')
    }

    /**
     * Run the selected checks. [onProgress] is called with (completed, total)
     * after each check so the UI can update a progress bar.
     */
    fun scan(
        target: String,
        checkIds: Set<String>,
        onProgress: (Int, Int) -> Unit = { _, _ -> }
    ): List<Finding> {
        val ctx = ScanContext(normalizeUrl(target))
        if (ctx.scopeHost.isEmpty()) {
            return listOf(
                Finding("scanner", "Invalid target", Severity.INFO, target,
                    detail = "Could not parse a host from the input.")
            )
        }
        val selected = allChecks.filter { it.id in checkIds }
        val results = mutableListOf<Finding>()
        selected.forEachIndexed { index, check ->
            results += runCatching { check.run(ctx) }.getOrDefault(emptyList())
            onProgress(index + 1, selected.size)
        }
        return results.sortedByDescending { it.severity.rank }
    }
}
