package com.strykerx.lab.core.resources

/** Snapshot of device resource state relevant to scan safety. */
data class DeviceStatus(
    val batteryPercent: Int,
    val isCharging: Boolean,
    val thermal: ThermalLevel,
    val lowStorage: Boolean
) {
    companion object {
        val UNKNOWN = DeviceStatus(
            batteryPercent = 100,
            isCharging = false,
            thermal = ThermalLevel.NONE,
            lowStorage = false
        )
    }
}

/** Normalized thermal level mapped from Android PowerManager thermal status. */
enum class ThermalLevel(val label: String, val unsafe: Boolean) {
    NONE("Normal", false),
    LIGHT("Light", false),
    MODERATE("Moderate", false),
    SEVERE("Severe", true),
    CRITICAL("Critical", true),
    EMERGENCY("Emergency", true),
    SHUTDOWN("Shutdown", true);

    companion object {
        /** Maps android.os.PowerManager THERMAL_STATUS_* ints to a level. */
        fun fromAndroid(status: Int): ThermalLevel = when (status) {
            0 -> NONE        // THERMAL_STATUS_NONE
            1 -> LIGHT       // THERMAL_STATUS_LIGHT
            2 -> MODERATE    // THERMAL_STATUS_MODERATE
            3 -> SEVERE      // THERMAL_STATUS_SEVERE
            4 -> CRITICAL    // THERMAL_STATUS_CRITICAL
            5 -> EMERGENCY   // THERMAL_STATUS_EMERGENCY
            6 -> SHUTDOWN    // THERMAL_STATUS_SHUTDOWN
            else -> NONE
        }
    }
}

/** Why a scan is (or would be) paused, or null if it may run. */
enum class PauseReason(val message: String) {
    LOW_BATTERY("Paused: battery below the profile threshold."),
    THERMAL("Paused: device temperature is in an unsafe range."),
    LOW_STORAGE("Paused: device storage is critically low.")
}

/**
 * Pure policy function: given a device status and profile, return the reason a
 * scan must pause, or null if it may proceed. Charging bypasses the battery
 * threshold but never the thermal or storage guards.
 */
fun evaluatePause(status: DeviceStatus, profile: ResourceProfile): PauseReason? {
    if (status.thermal.unsafe) return PauseReason.THERMAL
    if (status.lowStorage) return PauseReason.LOW_STORAGE
    if (!status.isCharging && status.batteryPercent < profile.batteryPausePercent) {
        return PauseReason.LOW_BATTERY
    }
    return null
}
