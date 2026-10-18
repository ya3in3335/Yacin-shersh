package com.strykerx.lab

import com.strykerx.lab.core.resources.ResourceProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResourceProfileTest {

    @Test
    fun eco_limits_are_conservative() {
        val p = ResourceProfile.ECO
        assertEquals(1, p.analysisWorkers)
        assertEquals(1, p.maxConnections)
        assertEquals(30, p.batteryPausePercent)
        assertFalse(p.requiresConfirmation)
    }

    @Test
    fun balanced_is_default_and_moderate() {
        assertEquals(ResourceProfile.BALANCED, ResourceProfile.DEFAULT)
        assertEquals(2, ResourceProfile.BALANCED.analysisWorkers)
        assertEquals(2, ResourceProfile.BALANCED.maxConnections)
        assertEquals(25, ResourceProfile.BALANCED.batteryPausePercent)
    }

    @Test
    fun advanced_caps_at_three_and_requires_confirmation() {
        val p = ResourceProfile.ADVANCED
        assertEquals(3, p.analysisWorkers)
        assertEquals(3, p.maxConnections)
        assertEquals(20, p.batteryPausePercent)
        assertTrue(p.requiresConfirmation)
    }

    @Test
    fun no_profile_exceeds_three_workers_or_connections() {
        ResourceProfile.entries.forEach {
            assertTrue(it.analysisWorkers in 1..3)
            assertTrue(it.maxConnections in 1..3)
        }
    }

    @Test
    fun from_falls_back_to_default_on_unknown() {
        assertEquals(ResourceProfile.DEFAULT, ResourceProfile.from("nonsense"))
        assertEquals(ResourceProfile.ADVANCED, ResourceProfile.from("advanced"))
    }
}
