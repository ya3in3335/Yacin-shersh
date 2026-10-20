package com.strykerx.lab

import com.strykerx.lab.scanner.web.InjectionCheck.Companion.isBlindSignal
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BlindSqliTest {

    @Test
    fun classic_blind_pattern_is_detected() {
        // true page ~= baseline (10000), false page clearly smaller
        assertTrue(isBlindSignal(base = 10000, t = 10000, f = 8000))
    }

    @Test
    fun no_difference_is_not_a_signal() {
        assertFalse(isBlindSignal(base = 10000, t = 10000, f = 10000))
    }

    @Test
    fun true_page_far_from_baseline_is_not_a_signal() {
        // both differ from baseline -> likely a dynamic page, not blind SQLi
        assertFalse(isBlindSignal(base = 10000, t = 7000, f = 8000))
    }

    @Test
    fun tiny_noise_within_tolerance_is_not_a_signal() {
        // false page differs by <5% -> below threshold
        assertFalse(isBlindSignal(base = 10000, t = 10050, f = 10200))
    }

    @Test
    fun zero_baseline_is_safe() {
        assertFalse(isBlindSignal(base = 0, t = 0, f = 0))
    }
}
