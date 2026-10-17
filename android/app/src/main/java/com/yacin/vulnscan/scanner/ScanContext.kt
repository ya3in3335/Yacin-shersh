package com.yacin.vulnscan.scanner

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.URI
import java.util.concurrent.TimeUnit

/**
 * Holds per-scan configuration and enforces that every request stays on the
 * single host the operator confirmed authorization for.
 */
class ScanContext(
    val baseUrl: String,
    timeoutSeconds: Long = 10,
    private val delayMs: Long = 250
) {
    val scopeHost: String = URI(baseUrl).host ?: ""

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .followRedirects(true)
        .retryOnConnectionFailure(true)
        .build()

    private var lastRequest = 0L

    fun inScope(url: String): Boolean =
        (runCatching { URI(url).host }.getOrNull() ?: "") == scopeHost

    /** Rate-limited, scope-enforced request. Returns null on error/out-of-scope. */
    @Synchronized
    fun execute(url: String, method: String = "GET"): Response? {
        if (!inScope(url)) return null
        val wait = delayMs - (System.currentTimeMillis() - lastRequest)
        if (wait > 0) Thread.sleep(wait)
        lastRequest = System.currentTimeMillis()

        val request = Request.Builder()
            .url(url)
            .method(method, null)
            .header("User-Agent", "VulnScan-Android/1.0 (authorized-testing)")
            .build()
        return runCatching { client.newCall(request).execute() }.getOrNull()
    }
}
