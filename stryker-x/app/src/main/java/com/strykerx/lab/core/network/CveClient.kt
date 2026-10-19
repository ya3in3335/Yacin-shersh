package com.strykerx.lab.core.network

import com.strykerx.lab.scanner.apk.DetectedComponent
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/** A known vulnerability affecting a detected component, from the online CVE DB. */
data class CveMatch(
    val component: DetectedComponent,
    val cveIds: List<String>,      // CVE-… / GHSA-… identifiers
    val summary: String,
    val severityLabel: String,     // CRITICAL / HIGH / MODERATE / LOW / UNKNOWN
    val count: Int,                // number of advisories matched
    val versionCertain: Boolean    // true when queried with an exact version
)

/** Result of a batch lookup, including whether the CVE service was reachable. */
data class CveLookupResult(
    val matches: List<CveMatch>,
    val online: Boolean,
    val queried: Int
)

/**
 * Looks up known vulnerabilities for detected third-party libraries against the
 * public OSV.dev database (https://osv.dev) — the open vulnerability database that
 * aggregates CVEs and GHSA advisories for Maven/Android ecosystems. No API key is
 * required. This connects ONLY to the CVE database, never to the analyzed app's
 * own servers. Calls are blocking and must run off the main thread.
 */
class CveClient(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .callTimeout(12, TimeUnit.SECONDS)
        .build(),
    private val endpoint: String = "https://api.osv.dev/v1/query"
) {
    private val jsonMedia = "application/json".toMediaType()

    fun lookupAll(components: List<DetectedComponent>): CveLookupResult {
        if (components.isEmpty()) return CveLookupResult(emptyList(), online = true, queried = 0)
        val matches = mutableListOf<CveMatch>()
        var anySuccess = false
        var anyFailure = false
        var queried = 0
        for (c in components.take(MAX_COMPONENTS)) {
            queried++
            when (val r = queryComponent(c)) {
                is QueryOutcome.Ok -> {
                    anySuccess = true
                    r.match?.let { matches += it }
                }
                QueryOutcome.Failed -> anyFailure = true
            }
        }
        // Online if at least one call got through; offline only if everything failed.
        val online = anySuccess || !anyFailure
        return CveLookupResult(matches, online, queried)
    }

    private sealed interface QueryOutcome {
        data class Ok(val match: CveMatch?) : QueryOutcome
        data object Failed : QueryOutcome
    }

    private fun queryComponent(c: DetectedComponent): QueryOutcome {
        val payload = JSONObject().apply {
            c.version?.let { put("version", it) }
            put("package", JSONObject().apply {
                put("name", c.coordinate)
                put("ecosystem", "Maven")
            })
        }
        val req = Request.Builder()
            .url(endpoint)
            .post(payload.toString().toRequestBody(jsonMedia))
            .header("Accept", "application/json")
            .build()
        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return QueryOutcome.Failed
                val body = resp.body?.string().orEmpty()
                QueryOutcome.Ok(parse(c, body))
            }
        } catch (_: IOException) {
            QueryOutcome.Failed
        } catch (_: Exception) {
            QueryOutcome.Failed
        }
    }

    private fun parse(c: DetectedComponent, body: String): CveMatch? {
        val root = runCatching { JSONObject(body) }.getOrNull() ?: return null
        val vulns = root.optJSONArray("vulns") ?: return null
        if (vulns.length() == 0) return null

        val ids = linkedSetOf<String>()
        var summary = ""
        var worst = 0 // rank: LOW=1, MODERATE=2, HIGH=3, CRITICAL=4
        for (i in 0 until vulns.length()) {
            val v = vulns.optJSONObject(i) ?: continue
            v.optString("id").takeIf { it.isNotBlank() }?.let { ids += it }
            v.optJSONArray("aliases")?.let { aliases ->
                for (j in 0 until aliases.length()) {
                    aliases.optString(j).takeIf { it.startsWith("CVE-") }?.let { ids += it }
                }
            }
            if (summary.isBlank()) {
                summary = v.optString("summary").ifBlank { v.optString("details") }.take(240)
            }
            val sev = v.optJSONObject("database_specific")?.optString("severity").orEmpty()
            worst = maxOf(worst, severityRank(sev))
        }
        if (ids.isEmpty()) return null
        // Prefer CVE identifiers in the displayed list.
        val sorted = ids.sortedByDescending { it.startsWith("CVE-") }
        return CveMatch(
            component = c,
            cveIds = sorted.take(MAX_IDS),
            summary = summary.ifBlank { "Known advisory for ${c.name}." },
            severityLabel = rankLabel(worst),
            count = vulns.length(),
            versionCertain = c.version != null
        )
    }

    private fun severityRank(s: String): Int = when (s.uppercase()) {
        "CRITICAL" -> 4
        "HIGH" -> 3
        "MODERATE", "MEDIUM" -> 2
        "LOW" -> 1
        else -> 0
    }

    private fun rankLabel(r: Int): String = when (r) {
        4 -> "CRITICAL"; 3 -> "HIGH"; 2 -> "MODERATE"; 1 -> "LOW"; else -> "UNKNOWN"
    }

    companion object {
        private const val MAX_COMPONENTS = 20
        private const val MAX_IDS = 12
    }
}
