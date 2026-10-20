package com.strykerx.lab

import com.strykerx.lab.core.resources.DeviceStatus
import com.strykerx.lab.core.resources.PauseReason
import com.strykerx.lab.core.resources.ResourceProfile
import com.strykerx.lab.core.resources.ThermalLevel
import com.strykerx.lab.core.resources.evaluatePause
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PausePolicyTest {

    private fun status(
        battery: Int = 100,
        charging: Boolean = false,
        thermal: ThermalLevel = ThermalLevel.NONE,
        lowStorage: Boolean = false
    ) = DeviceStatus(battery, charging, thermal, lowStorage)

    @Test
    fun healthy_device_may_run() {
        assertNull(evaluatePause(status(), ResourceProfile.BALANCED))
    }

    @Test
    fun low_battery_pauses_unless_charging() {
        assertEquals(
            PauseReason.LOW_BATTERY,
            evaluatePause(status(battery = 20), ResourceProfile.BALANCED)
        )
        assertNull(evaluatePause(status(battery = 20, charging = true), ResourceProfile.BALANCED))
    }

    @Test
    fun battery_threshold_is_profile_specific() {
        // 28% is below ECO(30) but above BALANCED(25)
        assertEquals(PauseReason.LOW_BATTERY, evaluatePause(status(battery = 28), ResourceProfile.ECO))
        assertNull(evaluatePause(status(battery = 28), ResourceProfile.BALANCED))
    }

    @Test
    fun unsafe_thermal_pauses_even_when_charging() {
        assertEquals(
            PauseReason.THERMAL,
            evaluatePause(status(charging = true, thermal = ThermalLevel.SEVERE), ResourceProfile.ADVANCED)
        )
    }

    @Test
    fun low_storage_pauses() {
        assertEquals(
            PauseReason.LOW_STORAGE,
            evaluatePause(status(lowStorage = true), ResourceProfile.BALANCED)
        )
    }

    @Test
    fun thermal_takes_precedence_over_battery() {
        val s = status(battery = 10, thermal = ThermalLevel.CRITICAL)
        assertEquals(PauseReason.THERMAL, evaluatePause(s, ResourceProfile.BALANCED))
    }
}
