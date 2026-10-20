package com.strykerx.lab.core.common

/** Immutable count of findings per severity. Pure data, unit-testable. */
data class SeverityStats(
    val critical: Int = 0,
    val high: Int = 0,
    val medium: Int = 0,
    val low: Int = 0,
    val info: Int = 0
) {
    val total: Int get() = critical + high + medium + low + info

    fun countFor(severity: Severity): Int = when (severity) {
        Severity.CRITICAL -> critical
        Severity.HIGH -> high
        Severity.MEDIUM -> medium
        Severity.LOW -> low
        Severity.INFO -> info
    }

    companion object {
        /** Reduce a list of severities into a [SeverityStats]. Pure function. */
        fun of(severities: List<Severity>): SeverityStats {
            var c = 0; var h = 0; var m = 0; var l = 0; var i = 0
            for (s in severities) when (s) {
                Severity.CRITICAL -> c++
                Severity.HIGH -> h++
                Severity.MEDIUM -> m++
                Severity.LOW -> l++
                Severity.INFO -> i++
            }
            return SeverityStats(c, h, m, l, i)
        }
    }
}
