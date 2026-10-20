package com.strykerx.lab.scanner.apk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

/** A device-installed app the user can pick for static analysis. */
data class InstalledApp(
    val label: String,
    val packageName: String,
    val sourceDir: String,
    val isSystem: Boolean
)

object InstalledApps {

    /**
     * Lists installed apps with a readable APK path. Requires the
     * QUERY_ALL_PACKAGES permission to see packages beyond the caller's own
     * on Android 11+. Returns user apps first, then system apps, A→Z.
     */
    @Suppress("DEPRECATION")
    fun list(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val apps = runCatching { pm.getInstalledApplications(0) }.getOrDefault(emptyList())
        return apps.mapNotNull { ai: ApplicationInfo ->
            val src = ai.publicSourceDir ?: ai.sourceDir ?: return@mapNotNull null
            val label = runCatching { pm.getApplicationLabel(ai).toString() }
                .getOrDefault(ai.packageName)
            InstalledApp(
                label = label,
                packageName = ai.packageName,
                sourceDir = src,
                isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            )
        }.sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
    }
}
