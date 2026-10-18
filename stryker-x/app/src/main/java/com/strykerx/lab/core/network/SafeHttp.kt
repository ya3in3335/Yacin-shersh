package com.strykerx.lab.core.network

import com.strykerx.lab.scanner.web.ScopePolicy
import com.strykerx.lab.scanner.web.ScopeResult
import com.strykerx.lab.scanner.web.ScopeValidator
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/** Lightweight captured response (body bounded to protect memory). */
data class HttpResult(
    val url: String,
    val code: Int,
    val headers: Map<String, List<String>>,
    val body: String,
    val finalUrl: String
) {
    fun header(name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, true) }?.value?.firstOrNull()

    fun headerValues(name: String): List<String> =
        headers.entries.firstOrNull { it.key.equals(name, true) }?.value ?: emptyList()
}

/**
 * Scope-enforcing, rate-limited HTTP client.
 *
 * Safety properties:
 *  - A custom [Dns] re-resolves every host and rejects private/reserved addresses
 *    (unless internal is approved), defeating DNS rebinding at connect time.
 *  - Redirects are handled manually; each hop is re-validated against scope so a
 *    redirect cannot expand the scope.
 *  - Response bodies are truncated to [maxBodyBytes]; requests time out.
 */
class SafeHttp(
    private val policy: ScopePolicy,
    private val pacingMs: Long,
    timeoutSeconds: Long = 15,
    private val maxBodyBytes: Long = 2L * 1024 * 1024,
    private val maxRedirects: Int = 5
) {
    private var lastRequest = 0L

    private val scopeDns = Dns { hostname ->
        val resolved = Dns.SYSTEM.lookup(hostname)
        val filtered = if (policy.allowInternalNetwork) resolved
        else resolved.filterNot { ScopeValidator.isPrivateOrReserved(it) }
        if (filtered.isEmpty()) {
            throw UnknownHostException("Blocked by scope policy: $hostname resolves only to disallowed addresses")
        }
        filtered
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .dns(scopeDns)
        .build()

    fun resolver(host: String): List<InetAddress> =
        runCatching { Dns.SYSTEM.lookup(host) }.getOrDefault(emptyList())

    @Synchronized
    private fun pace() {
        val wait = pacingMs - (System.currentTimeMillis() - lastRequest)
        if (wait > 0) Thread.sleep(wait)
        lastRequest = System.currentTimeMillis()
    }

    /** GET with manual, scope-checked redirect handling. Returns null on error/out-of-scope. */
    fun get(url: String, method: String = "GET"): HttpResult? {
        var currentUrl = url
        var redirects = 0
        while (true) {
            when (val v = ScopeValidator.validate(currentUrl, policy, ::resolver)) {
                is ScopeResult.Rejected -> return null
                is ScopeResult.Allowed -> currentUrl = v.normalizedUrl
            }
            pace()
            val request = Request.Builder()
                .url(currentUrl)
                .method(method, null)
                .header("User-Agent", "STRYKER-X/1.0 (authorized-testing)")
                .build()

            val response: Response = runCatching { client.newCall(request).execute() }
                .getOrNull() ?: return null

            response.use {
                val code = it.code
                if (code in 300..399 && redirects < maxRedirects) {
                    val location = it.header("Location")
                    if (location != null) {
                        redirects++
                        currentUrl = resolveLocation(currentUrl, location)
                        return@use
                    }
                }
                return HttpResult(
                    url = url,
                    code = code,
                    headers = it.headers.toMultimap(),
                    body = it.peekBody(maxBodyBytes).string(),
                    finalUrl = currentUrl
                )
            }
            // If we reach here a redirect was followed; loop to re-validate the next hop.
        }
    }

    private fun resolveLocation(base: String, location: String): String =
        runCatching {
            java.net.URI(base).resolve(location).toString()
        }.getOrDefault(location)
}
