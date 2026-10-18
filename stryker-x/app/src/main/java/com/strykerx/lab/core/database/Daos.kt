package com.strykerx.lab.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface TargetDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(target: TargetEntity)

    @Query("SELECT * FROM targets WHERE id = :id")
    suspend fun byId(id: String): TargetEntity?
}

@Dao
interface ScopeDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(scope: ScopeEntity)

    @Query("SELECT * FROM scopes WHERE targetId = :targetId ORDER BY createdAt DESC LIMIT 1")
    suspend fun latestForTarget(targetId: String): ScopeEntity?
}

@Dao
interface ScanSessionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(session: ScanSessionEntity)

    @Query("UPDATE scan_sessions SET state = :state, finishedAt = :finishedAt WHERE id = :id")
    suspend fun updateState(id: String, state: String, finishedAt: Long?)

    @Query("SELECT * FROM scan_sessions ORDER BY startedAt DESC LIMIT :limit")
    fun recent(limit: Int): Flow<List<ScanSessionEntity>>

    @Query("SELECT COUNT(*) FROM scan_sessions WHERE state = 'COMPLETED'")
    fun completedCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_sessions WHERE state IN ('RUNNING','PAUSED','QUEUED')")
    fun activeCount(): Flow<Int>

    @Query("DELETE FROM scan_sessions")
    suspend fun deleteAll()
}

@Dao
interface FindingDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfNew(finding: FindingEntity): Long

    @Query("SELECT COUNT(*) FROM findings WHERE sessionId = :sessionId AND dedupeKey = :key")
    suspend fun countByDedupe(sessionId: String, key: String): Int

    @Query("SELECT * FROM findings ORDER BY createdAt DESC")
    fun all(): Flow<List<FindingEntity>>

    @Query("SELECT * FROM findings WHERE sessionId = :sessionId ORDER BY createdAt DESC")
    fun forSession(sessionId: String): Flow<List<FindingEntity>>

    @Query("SELECT severity FROM findings")
    fun allSeverities(): Flow<List<String>>

    @Query("SELECT COUNT(*) FROM findings WHERE verificationStatus = 'CONFIRMED'")
    fun confirmedCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM findings WHERE verificationStatus IN ('POTENTIAL','UNVERIFIED')")
    fun potentialCount(): Flow<Int>

    @Query("DELETE FROM findings")
    suspend fun deleteAll()
}

@Dao
interface ErrorLogDao {
    @Insert
    suspend fun insert(log: ErrorLogEntity)

    @Query("DELETE FROM error_logs")
    suspend fun deleteAll()
}
