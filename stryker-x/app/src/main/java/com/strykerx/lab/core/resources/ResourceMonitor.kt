package com.strykerx.lab.core.resources

import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import android.os.StatFs
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Samples battery, thermal and storage state on demand (no continuous polling,
 * per the Resource Protection Engine safeguards). Call [refresh] when a screen
 * becomes visible or before/within a scan loop.
 */
class ResourceMonitor(private val appContext: Context) {

    private val _status = MutableStateFlow(DeviceStatus.UNKNOWN)
    val status: StateFlow<DeviceStatus> = _status.asStateFlow()

    fun refresh(): DeviceStatus {
        val snapshot = sample()
        _status.value = snapshot
        return snapshot
    }

    private fun sample(): DeviceStatus {
        val bm = appContext.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        val percent = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            ?.takeIf { it in 0..100 } ?: 100
        val charging = bm?.isCharging ?: false

        val thermal = runCatching {
            val pm = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
            ThermalLevel.fromAndroid(pm.currentThermalStatus)
        }.getOrDefault(ThermalLevel.NONE)

        val lowStorage = runCatching {
            val stat = StatFs(appContext.filesDir.absolutePath)
            val freeBytes = stat.availableBytes
            freeBytes < LOW_STORAGE_THRESHOLD_BYTES
        }.getOrDefault(false)

        return DeviceStatus(
            batteryPercent = percent,
            isCharging = charging,
            thermal = thermal,
            lowStorage = lowStorage
        )
    }

    companion object {
        private const val LOW_STORAGE_THRESHOLD_BYTES = 100L * 1024 * 1024 // 100 MB
    }
}
