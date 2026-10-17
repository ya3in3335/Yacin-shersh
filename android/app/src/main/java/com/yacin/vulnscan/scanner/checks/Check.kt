package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext

/** A single scanner module. Must not throw; return an empty list on failure. */
interface Check {
    val id: String
    fun run(ctx: ScanContext): List<Finding>
}
