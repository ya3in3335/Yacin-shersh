package com.strykerx.lab.core.common

import com.strykerx.lab.core.database.FindingDao
import com.strykerx.lab.core.database.ScanSessionDao
import com.strykerx.lab.core.database.ScanSessionEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** Read-side repository that surfaces persisted state to the UI layer. */
class StrykerRepository(
    private val scanSessionDao: ScanSessionDao,
    private val findingDao: FindingDao
) {
    val completedScans: Flow<Int> = scanSessionDao.completedCount()
    val activeScans: Flow<Int> = scanSessionDao.activeCount()
    val confirmedFindings: Flow<Int> = findingDao.confirmedCount()
    val potentialFindings: Flow<Int> = findingDao.potentialCount()

    val severityStats: Flow<SeverityStats> =
        findingDao.allSeverities().map { names ->
            SeverityStats.of(names.map { Severity.from(it) })
        }

    fun recentSessions(limit: Int = 10): Flow<List<ScanSessionEntity>> =
        scanSessionDao.recent(limit)

    suspend fun clearHistory() {
        findingDao.deleteAll()
        scanSessionDao.deleteAll()
    }
}
