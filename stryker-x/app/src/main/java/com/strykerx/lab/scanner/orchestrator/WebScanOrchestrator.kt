package com.strykerx.lab.scanner.orchestrator

import com.strykerx.lab.core.common.ScanState
import com.strykerx.lab.core.database.ErrorLogEntity
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.core.database.FindingDao
import com.strykerx.lab.core.database.ErrorLogDao
import com.strykerx.lab.core.database.ScanSessionDao
import com.strykerx.lab.core.database.ScanSessionEntity
import com.strykerx.lab.core.database.ScopeDao
import com.strykerx.lab.core.database.ScopeEntity
import com.strykerx.lab.core.database.TargetDao
import com.strykerx.lab.core.database.TargetEntity
import com.strykerx.lab.core.network.SafeHttp
import com.strykerx.lab.core.resources.ResourceMonitor
import com.strykerx.lab.core.resources.ResourceProfile
import com.strykerx.lab.core.resources.evaluatePause
import com.strykerx.lab.scanner.web.ContentSecurityCheck
import com.strykerx.lab.scanner.web.CorsCheck
import com.strykerx.lab.scanner.web.ExposureCheck
import com.strykerx.lab.scanner.web.FingerprintCheck
import com.strykerx.lab.scanner.web.HeaderCheck
import com.strykerx.lab.scanner.web.InjectionCheck
import com.strykerx.lab.scanner.web.PassiveReconCheck
import com.strykerx.lab.scanner.web.ScopePolicy
import com.strykerx.lab.scanner.web.ScopeResult
import com.strykerx.lab.scanner.web.ScopeValidator
import com.strykerx.lab.scanner.web.TlsCheck
import com.strykerx.lab.scanner.web.WebCheck
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.util.UUID

/** Parameters for a single authorized web scan. */
data class WebScanRequest(
    val targetUrl: String,
    val allowlist: Set<String>,
    val authorizationDeclared: Boolean,
    val allowActiveTests: Boolean,
    val allowInternalNetwork: Boolean
)

/** Outcome summary returned to the UI. */
data class WebScanOutcome(
    val sessionId: String,
    val state: ScanState,
    val findingsStored: Int,
    val message: String
)

/**
 * Coordinates an authorized web scan: scope verification, passive recon +
 * configuration checks, finding correlation/dedup, persistence and state
 * transitions. Honors the resource profile (pacing) and the pause policy, and
 * is cancellable via coroutine cancellation (Stop Scan).
 */
class WebScanOrchestrator(
    private val targetDao: TargetDao,
    private val scopeDao: ScopeDao,
    private val sessionDao: ScanSessionDao,
    private val findingDao: FindingDao,
    private val errorLogDao: ErrorLogDao,
    private val resourceMonitor: ResourceMonitor
) {
    /** Passive + configuration checks always run; injection is opt-in and scope-gated. */
    private fun checksFor(policy: ScopePolicy): List<WebCheck> = buildList {
        add(TlsCheck())
        add(HeaderCheck())
        add(ContentSecurityCheck())
        add(CorsCheck())
        add(FingerprintCheck())
        add(PassiveReconCheck())
        add(ExposureCheck())
        if (policy.allowActiveTests) add(InjectionCheck())
    }

    suspend fun run(
        request: WebScanRequest,
        profile: ResourceProfile,
        onProgress: (completed: Int, total: Int) -> Unit = { _, _ -> }
    ): WebScanOutcome = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val baseUrl = ScopeValidator.normalizeUrl(request.targetUrl)
        val syntax = ScopeValidator.validateSyntax(baseUrl)
        val host = (syntax as? ScopeResult.Allowed)?.host ?: ""

        val targetId = UUID.randomUUID().toString()
        val sessionId = UUID.randomUUID().toString()

        val policy = ScopePolicy(
            targetHost = host,
            allowlist = request.allowlist,
            authorizationDeclared = request.authorizationDeclared,
            allowActiveTests = request.allowActiveTests,
            allowInternalNetwork = request.allowInternalNetwork
        )
        val checks = checksFor(policy)
        val total = checks.size

        targetDao.upsert(TargetEntity(targetId, baseUrl, host, "WEBSITE", now))
        scopeDao.upsert(
            ScopeEntity(
                id = UUID.randomUUID().toString(),
                targetId = targetId,
                allowlist = request.allowlist.joinToString("\n"),
                authorizationDeclared = request.authorizationDeclared,
                allowActiveTests = request.allowActiveTests,
                allowInternalNetwork = request.allowInternalNetwork,
                maxRequestsPerSecond = (1000 / profile.requestPacingMs.coerceAtLeast(1)).toInt(),
                createdAt = now
            )
        )
        sessionDao.upsert(
            ScanSessionEntity(
                id = sessionId, targetId = targetId, profile = profile.name,
                state = ScanState.RUNNING.name, startedAt = now, finishedAt = null,
                totalChecks = total, completedChecks = 0, checkpoint = null
            )
        )

        // Stage A — scope verification (with DNS resolution).
        val http = SafeHttp(policy, pacingMs = profile.requestPacingMs)
        val verify = ScopeValidator.validate(baseUrl, policy, http::resolver)
        if (verify is ScopeResult.Rejected) {
            errorLogDao.insert(ErrorLogEntity(sessionId = sessionId, message = verify.reason, createdAt = System.currentTimeMillis()))
            sessionDao.updateState(sessionId, ScanState.FAILED.name, System.currentTimeMillis())
            return@withContext WebScanOutcome(sessionId, ScanState.FAILED, 0, verify.reason)
        }

        var stored = 0
        var completed = 0
        try {
            for (check in checks) {
                currentCoroutineContext().ensureActive() // honors Stop Scan

                val status = resourceMonitor.refresh()
                val pause = evaluatePause(status, profile)
                if (pause != null) {
                    errorLogDao.insert(ErrorLogEntity(sessionId = sessionId, message = pause.message, createdAt = System.currentTimeMillis()))
                    sessionDao.upsert(runningSession(sessionId, targetId, profile, total, completed, now).copy(state = ScanState.PAUSED.name))
                    return@withContext WebScanOutcome(sessionId, ScanState.PAUSED, stored, pause.message)
                }

                val findings = runCatching { check.run(http, baseUrl) }.getOrDefault(emptyList())
                for (f in findings) {
                    if (findingDao.countByDedupe(sessionId, f.dedupeKey) == 0) {
                        findingDao.insertIfNew(
                            FindingEntity(
                                id = UUID.randomUUID().toString(),
                                sessionId = sessionId,
                                findingCode = f.code,
                                title = f.title,
                                target = baseUrl,
                                affected = f.affected,
                                detectionMethod = f.detectionMethod,
                                evidence = f.evidence,
                                severity = f.severity.name,
                                confidence = f.confidence.name,
                                verificationStatus = f.verification.name,
                                reproduction = f.reproduction,
                                remediation = f.remediation,
                                dedupeKey = f.dedupeKey,
                                createdAt = System.currentTimeMillis()
                            )
                        )
                        stored++
                    }
                }
                completed++
                onProgress(completed, total)
            }
        } catch (ce: kotlinx.coroutines.CancellationException) {
            sessionDao.updateState(sessionId, ScanState.CANCELLED.name, System.currentTimeMillis())
            throw ce
        } catch (t: Throwable) {
            errorLogDao.insert(ErrorLogEntity(sessionId = sessionId, message = t.message ?: t.javaClass.simpleName, createdAt = System.currentTimeMillis()))
            sessionDao.upsert(runningSession(sessionId, targetId, profile, total, completed, now).copy(state = ScanState.FAILED.name))
            return@withContext WebScanOutcome(sessionId, ScanState.FAILED, stored, "Scan failed: ${t.message}")
        }

        sessionDao.upsert(runningSession(sessionId, targetId, profile, total, completed, now).copy(state = ScanState.COMPLETED.name, finishedAt = System.currentTimeMillis()))
        WebScanOutcome(sessionId, ScanState.COMPLETED, stored, "Scan completed: $stored finding(s).")
    }

    private fun runningSession(
        id: String, targetId: String, profile: ResourceProfile,
        total: Int, completed: Int, startedAt: Long
    ) = ScanSessionEntity(
        id = id, targetId = targetId, profile = profile.name, state = ScanState.RUNNING.name,
        startedAt = startedAt, finishedAt = null, totalChecks = total,
        completedChecks = completed, checkpoint = null
    )
}
