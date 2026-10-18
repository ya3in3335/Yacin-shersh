package com.strykerx.lab.scanner.apk

import android.content.Context
import android.net.Uri
import com.strykerx.lab.core.common.ScanState
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
    private val errorLogDao: ErrorLogDao
) {
    suspend fun analyze(uri: Uri): ApkScanOutcome = withContext(Dispatchers.IO) {
        val cache = File(appContext.cacheDir, "apk-import").apply { mkdirs() }
        val apk = File(cache, "import-${System.currentTimeMillis()}.apk")
        try {
            val copied = copyBounded(uri, apk, ApkAnalyzer.MAX_APK_BYTES)
            if (copied < 0) {
                return@withContext ApkScanOutcome(
                    null, null,
                    "File is too large (limit ${ApkAnalyzer.MAX_APK_BYTES / (1024 * 1024)} MB) or could not be read."
                )
            }

            val report = ApkAnalyzer.analyze(appContext, apk)
            if (!report.ok) {
                return@withContext ApkScanOutcome(null, report, report.error ?: "Analysis failed.")
            }

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
            for (fnd in report.findings) {
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
            ApkScanOutcome(sessionId, report, "Analysis complete: ${report.findings.size} finding(s).")
        } catch (t: Throwable) {
            errorLogDao.insert(ErrorLogEntity(sessionId = null, message = t.message ?: t.javaClass.simpleName, createdAt = System.currentTimeMillis()))
            ApkScanOutcome(null, null, "Analysis error: ${t.message}")
        } finally {
            runCatching { apk.delete() }
        }
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
