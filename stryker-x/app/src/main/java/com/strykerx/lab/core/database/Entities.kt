package com.strykerx.lab.core.database

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** A scan target (website, API, APK or network range). */
@Entity(tableName = "targets")
data class TargetEntity(
    @PrimaryKey val id: String,
    val url: String,
    val host: String,
    val kind: String,          // WEBSITE | API | APK | NETWORK
    val createdAt: Long
)

/** Authorized scope + authorization declaration for a target. */
@Entity(
    tableName = "scopes",
    indices = [Index("targetId")]
)
data class ScopeEntity(
    @PrimaryKey val id: String,
    val targetId: String,
    val allowlist: String,            // newline-separated hosts/CIDRs
    val authorizationDeclared: Boolean,
    val allowActiveTests: Boolean,
    val allowInternalNetwork: Boolean,
    val maxRequestsPerSecond: Int,
    val createdAt: Long
)

/** A scan session / orchestrated run. */
@Entity(
    tableName = "scan_sessions",
    indices = [Index("targetId")]
)
data class ScanSessionEntity(
    @PrimaryKey val id: String,
    val targetId: String,
    val profile: String,              // ResourceProfile name
    val state: String,                // ScanState name
    val startedAt: Long,
    val finishedAt: Long?,
    val totalChecks: Int,
    val completedChecks: Int,
    val checkpoint: String?           // resumable checkpoint, JSON, nullable
)

/** A single finding produced during a session. */
@Entity(
    tableName = "findings",
    indices = [Index("sessionId"), Index("dedupeKey")]
)
data class FindingEntity(
    @PrimaryKey val id: String,
    val sessionId: String,
    val findingCode: String,
    val title: String,
    val target: String,
    val affected: String,
    val detectionMethod: String,
    val evidence: String,
    val severity: String,             // Severity name
    val confidence: String,           // Confidence name
    val verificationStatus: String,   // VerificationStatus name
    val reproduction: String,
    val remediation: String,
    val dedupeKey: String,            // used to deduplicate equivalent findings
    val createdAt: Long
)

/** Error entry attached to a session for diagnostics. */
@Entity(
    tableName = "error_logs",
    indices = [Index("sessionId")]
)
data class ErrorLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: String?,
    val message: String,
    val createdAt: Long
)
