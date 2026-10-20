package com.strykerx.lab.core.resources

/**
 * Resource budget profile. Governs concurrency, pacing and the battery level
 * below which scans pause. Memory budgets are best-effort targets, not OS
 * guarantees. See the Resource Protection Engine requirement.
 */
enum class ResourceProfile(
    val displayName: String,
    val analysisWorkers: Int,
    val maxConnections: Int,
    val requestPacingMs: Long,
    val batteryPausePercent: Int,
    val requiresConfirmation: Boolean
) {
    ECO(
        displayName = "Eco",
        analysisWorkers = 1,
        maxConnections = 1,
        requestPacingMs = 900,
        batteryPausePercent = 30,
        requiresConfirmation = false
    ),
    BALANCED(
        displayName = "Balanced",
        analysisWorkers = 2,
        maxConnections = 2,
        requestPacingMs = 400,
        batteryPausePercent = 25,
        requiresConfirmation = false
    ),
    ADVANCED(
        displayName = "Advanced",
        analysisWorkers = 3,
        maxConnections = 3,
        requestPacingMs = 150,
        batteryPausePercent = 20,
        requiresConfirmation = true
    );

    companion object {
        val DEFAULT = BALANCED

        fun from(value: String?): ResourceProfile =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: DEFAULT
    }
}
