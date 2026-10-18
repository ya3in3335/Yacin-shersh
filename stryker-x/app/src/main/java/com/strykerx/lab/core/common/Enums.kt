package com.strykerx.lab.core.common

/** Severity of a finding. Ordered from most to least severe by [rank]. */
enum class Severity(val label: String, val rank: Int) {
    CRITICAL("Critical", 4),
    HIGH("High", 3),
    MEDIUM("Medium", 2),
    LOW("Low", 1),
    INFO("Informational", 0);

    companion object {
        fun from(value: String?): Severity =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: INFO
    }
}

/** How much confidence the scanner has in a finding. */
enum class Confidence(val label: String) {
    HIGH("High"), MEDIUM("Medium"), LOW("Low");

    companion object {
        fun from(value: String?): Confidence =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: LOW
    }
}

/**
 * Verification status of a finding. A scanner alert alone is never [CONFIRMED];
 * confirmation requires reproducible evidence.
 */
enum class VerificationStatus(val label: String) {
    CONFIRMED("Confirmed"),
    POTENTIAL("Potential"),
    UNVERIFIED("Unverified"),
    FALSE_POSITIVE("False Positive"),
    INFORMATIONAL("Informational");

    companion object {
        fun from(value: String?): VerificationStatus =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: UNVERIFIED
    }
}

/** Lifecycle state of a scan session / orchestrated task. */
enum class ScanState {
    QUEUED, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED;

    val isTerminal: Boolean get() = this == COMPLETED || this == FAILED || this == CANCELLED

    companion object {
        fun from(value: String?): ScanState =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: QUEUED
    }
}
