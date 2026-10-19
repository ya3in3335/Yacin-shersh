package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Detects exposed GraphQL endpoints (read-only probe). */
class GraphQLCheck : WebCheck {
    override val id = "graphql"
    override val displayName = "GraphQL Endpoint"

    private val paths = listOf("/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/query")
    private val hint = Regex("(?i)(\"errors\"|must provide query|graphql|GET query missing|operationName|__schema)")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()
        for (path in paths) {
            val resp = http.get(baseUrl + path) ?: continue
            if (resp.code !in listOf(200, 400, 405, 422)) continue
            if (ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) continue
            if (!hint.containsMatchIn(resp.body.take(20_000))) continue
            return listOf(
                WebFinding(
                    code = "graphql-endpoint",
                    title = "GraphQL endpoint exposed: $path",
                    affected = resp.finalUrl,
                    detectionMethod = "Read-only endpoint probe",
                    evidence = "Response (HTTP ${resp.code}) matches GraphQL behavior: " +
                        resp.body.take(200).replace('\n', ' '),
                    severity = Severity.LOW,
                    confidence = Confidence.MEDIUM,
                    verification = VerificationStatus.CONFIRMED,
                    reproduction = "Fetch ${resp.finalUrl}.",
                    remediation = "Disable introspection in production, enforce auth/rate-limits, and avoid verbose errors. Review for authorization flaws."
                )
            )
        }
        return emptyList()
    }
}
