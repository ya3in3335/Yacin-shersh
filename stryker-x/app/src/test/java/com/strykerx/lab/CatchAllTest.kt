package com.strykerx.lab

import com.strykerx.lab.scanner.web.ExposureCheck.Companion.looksLikeCatchAll
import com.strykerx.lab.scanner.web.ExposureCheck.PageSignature
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CatchAllTest {

    private val spaPage = PageSignature(200, 326014, "<!doctype html><html><head><title>Dizy</title>")

    @Test
    fun identical_spa_page_is_detected_as_catch_all() {
        val candidate = PageSignature(200, 326014, "<!doctype html><html><head><title>Dizy</title>")
        assertTrue(looksLikeCatchAll(spaPage, candidate))
    }

    @Test
    fun a_real_different_file_is_not_catch_all() {
        val realEnv = PageSignature(200, 180, "APP_KEY=base64:...\nDB_PASSWORD=...")
        assertFalse(looksLikeCatchAll(spaPage, realEnv))
    }

    @Test
    fun no_baseline_means_not_filtered() {
        val candidate = PageSignature(200, 180, "APP_KEY=...")
        assertFalse(looksLikeCatchAll(null, candidate))
    }

    @Test
    fun baseline_that_is_a_real_404_does_not_filter_200s() {
        val proper404 = PageSignature(404, 120, "Not Found")
        val candidate = PageSignature(200, 180, "APP_KEY=...")
        assertFalse(looksLikeCatchAll(proper404, candidate))
    }

    @Test
    fun same_length_but_different_prefix_is_not_catch_all() {
        val candidate = PageSignature(200, 326014, "COMPLETELY DIFFERENT CONTENT HERE ....")
        assertFalse(looksLikeCatchAll(spaPage, candidate))
    }
}
