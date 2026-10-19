package com.strykerx.lab.scanner.apk

import android.content.Context
import android.net.Uri
import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.ScanState
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.CveClient
import com.strykerx.lab.core.network.CveMatch
import com.strykerx.lab.scanner.web.WebFinding
import com.strykerx.lab.core.database.ErrorLogDao
import com.strykerx.lab.core.database.ErrorLogEntity
import com.strykerx.lab.core.database.FindingDao
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.core.database.ScanSessionDao
import com.strykerx.lab.core.database.ScanSessionEntity
import com.strykerx.lab.core.database.TargetDao
import com.strykerx.lab.core.database.TargetEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

data class ApkScanOutcome(
    val sessionId: String?,
    val report: ApkReport?,
    val message: String
)

/**
 * Imports a user-picked APK (Storage Access Framework Uri), copies it to the
 * app cache under a strict size cap, runs the static [ApkAnalyzer], and persists
 * the session + findings. The imported APK is never executed; the cache copy is
 * deleted afterwards.
 */
class ApkScanOrchestrator(
    private val appContext: Context,
    private val targetDao: TargetDao,
    private val sessionDao: ScanSessionDao,
    private val findingDao: FindingDao,
    private val errorLogDao: ErrorLogDao,
    private val cveClient: CveClient = CveClient()
) {
    /** Analyze an imported APK (content Uri). The copy is deleted afterwards. */
    suspend fun analyze(uri: Uri): ApkScanOutcome = withContext(Dispatchers.IO) {
        val cache = File(appContext.cacheDir, "apk-import").apply { mkdirs() }
        val apk = File(cache, "import-${System.currentTimeMillis()}.apk")
        val copied = copyBounded(uri, apk, ApkAnalyzer.MAX_APK_BYTES)
        if (copied < 0) {
            runCatching { apk.delete() }
            return@withContext ApkScanOutcome(
                null, null,
                "File is too large (limit ${ApkAnalyzer.MAX_APK_BYTES / (1024 * 1024)} MB) or could not be read."
            )
        }
        analyzeFile(apk, deleteAfter = true)
    }

    /** Lists installed apps the user can pick for analysis. */
    suspend fun installedApps(): List<InstalledApp> = withContext(Dispatchers.IO) {
        InstalledApps.list(appContext)
    }

    /** Analyze an installed app by its on-device APK path (no copy needed). */
    suspend fun analyzeInstalled(sourceDir: String): ApkScanOutcome = withContext(Dispatchers.IO) {
        val apk = File(sourceDir)
        if (!apk.exists() || !apk.canRead()) {
            return@withContext ApkScanOutcome(null, null, "Cannot read the app's APK (protected or unavailable).")
        }
        analyzeFile(apk, deleteAfter = false)
    }

    private suspend fun analyzeFile(apk: File, deleteAfter: Boolean): ApkScanOutcome {
        try {
            val report = ApkAnalyzer.analyze(appContext, apk)
            if (!report.ok) {
                return ApkScanOutcome(null, report, report.error ?: "Analysis failed.")
            }

            // Enrich with known CVEs for detected libraries (online, OSV.dev).
            val cveFindings = cveEnrichment(report.packageName, report.components)
            val allFindings = report.findings + cveFindings

            val now = System.currentTimeMillis()
            val targetId = UUID.randomUUID().toString()
            val sessionId = UUID.randomUUID().toString()
            targetDao.upsert(TargetEntity(targetId, report.packageName, report.packageName, "APK", now))
            sessionDao.upsert(
                ScanSessionEntity(
                    id = sessionId, targetId = targetId, profile = "APK",
                    state = ScanState.RUNNING.name, startedAt = now, finishedAt = null,
                    totalChecks = 1, completedChecks = 1, checkpoint = null
                )
            )
            var stored = 0
            for (fnd in allFindings) {
                if (findingDao.countByDedupe(sessionId, fnd.dedupeKey) == 0) {
                    findingDao.insertIfNew(
                        FindingEntity(
                            id = UUID.randomUUID().toString(),
                            sessionId = sessionId,
                            findingCode = fnd.code,
                            title = fnd.title,
                            target = report.packageName,
                            affected = fnd.affected,
                            detectionMethod = fnd.detectionMethod,
                            evidence = fnd.evidence,
                            severity = fnd.severity.name,
                            confidence = fnd.confidence.name,
                            verificationStatus = fnd.verification.name,
                            reproduction = fnd.reproduction,
                            remediation = fnd.remediation,
                            dedupeKey = fnd.dedupeKey,
                            createdAt = System.currentTimeMillis()
                        )
                    )
                    stored++
                }
            }
            sessionDao.upsert(
                ScanSessionEntity(
                    id = sessionId, targetId = targetId, profile = "APK",
                    state = ScanState.COMPLETED.name, startedAt = now,
                    finishedAt = System.currentTimeMillis(), totalChecks = 1,
                    completedChecks = 1, checkpoint = null
                )
            )
            return ApkScanOutcome(
                sessionId, report.copy(findings = allFindings),
                "Analysis complete: ${allFindings.size} finding(s)" +
                    (if (cveFindings.isNotEmpty()) ", ${cveFindings.size} with known CVEs." else ".")
            )
        } catch (t: Throwable) {
            errorLogDao.insert(ErrorLogEntity(sessionId = null, message = t.message ?: t.javaClass.simpleName, createdAt = System.currentTimeMillis()))
            return ApkScanOutcome(null, null, "Analysis error: ${t.message}")
        } finally {
            // Only delete our own cache copy, never an installed app's real APK.
            if (deleteAfter) runCatching { apk.delete() }
        }
    }

    /**
     * Queries the online CVE database (OSV.dev) for the detected libraries and
     * turns matches into findings. Connects only to the CVE service; never to the
     * analyzed app's servers. Fails safe (returns an informational note) offline.
     */
    private fun cveEnrichment(pkg: String, components: List<DetectedComponent>): List<WebFinding> {
        if (components.isEmpty()) return emptyList()
        // Query exact-version components first — those yield CONFIRMED CVE matches.
        val ordered = components.sortedByDescending { it.version != null }
        val result = runCatching { cveClient.lookupAll(ordered) }.getOrNull()
            ?: return emptyList()
        val out = mutableListOf<WebFinding>()
        if (!result.online) {
            out += WebFinding(
                code = "apk-cve-offline",
                title = "CVE lookup skipped (offline)",
                affected = pkg,
                detectionMethod = "Online CVE database (OSV.dev)",
                evidence = "Could not reach the CVE database; ${components.size} detected component(s) were not checked for known vulnerabilities.",
                severity = Severity.INFO,
                confidence = Confidence.LOW,
                verification = VerificationStatus.INFORMATIONAL,
                reproduction = "Re-run the scan with an internet connection to enable CVE enrichment.",
                remediation = "Connect to the internet and re-scan to match bundled libraries against known CVEs."
            )
            return out
        }
        for (m in result.matches) out += cveFinding(pkg, m)
        return out
    }

    private fun cveFinding(pkg: String, m: CveMatch): WebFinding {
        val lib = m.component
        val libLabel = lib.name + (lib.version?.let { " v$it" } ?: "")
        val severity = when (m.severityLabel) {
            "CRITICAL" -> Severity.CRITICAL
            "HIGH" -> Severity.HIGH
            "MODERATE" -> Severity.MEDIUM
            "LOW" -> Severity.LOW
            else -> Severity.MEDIUM
        }
        val certain = m.versionCertain
        val ids = m.cveIds.joinToString(", ")
        return WebFinding(
            code = "apk-cve-${lib.coordinate}",
            title = "Known-vulnerable library: $libLabel (${m.count} advisory/advisories)",
            affected = "$pkg → ${lib.coordinate}",
            detectionMethod = "Online CVE database (OSV.dev)",
            evidence = buildString {
                append("Advisories: ").append(ids)
                if (m.summary.isNotBlank()) append("\n").append(m.summary)
                append("\n")
                append(if (certain) "Matched against the detected version v${lib.version}."
                       else "Version could not be extracted statically — verify the bundled version against the affected ranges.")
            },
            severity = severity,
            confidence = if (certain) Confidence.HIGH else Confidence.MEDIUM,
            verification = if (certain) VerificationStatus.CONFIRMED else VerificationStatus.POTENTIAL,
            reproduction = "Look up ${m.cveIds.firstOrNull() ?: "the advisory"} on osv.dev / nvd.nist.gov and compare with the library version shipped in the APK.",
            remediation = "Upgrade ${lib.name} to a fixed release (see the advisories), or remove the dependency if unused."
        )
    }

    /** Copies the Uri to [dest], aborting (returns -1) if it exceeds [max] bytes. */
    private fun copyBounded(uri: Uri, dest: File, max: Long): Long {
        val input = runCatching { appContext.contentResolver.openInputStream(uri) }.getOrNull() ?: return -1
        input.use { ins ->
            dest.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > max) {
                        runCatching { dest.delete() }
                        return -1
                    }
                    out.write(buf, 0, n)
                }
                return total
            }
        }
    }
}
