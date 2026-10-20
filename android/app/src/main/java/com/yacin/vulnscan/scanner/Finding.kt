package com.yacin.vulnscan.scanner

enum class Severity(val label: String, val rank: Int) {
    CRITICAL("CRITICAL", 4),
    HIGH("HIGH", 3),
    MEDIUM("MEDIUM", 2),
    LOW("LOW", 1),
    INFO("INFO", 0)
}

data class Finding(
    val check: String,
    val title: String,
    val severity: Severity,
    val target: String,
    val detail: String = "",
    val evidence: String = "",
    val remediation: String = ""
)
