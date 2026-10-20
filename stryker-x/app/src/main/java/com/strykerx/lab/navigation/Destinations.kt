package com.strykerx.lab.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Api
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.ui.graphics.vector.ImageVector

/** Top-level destinations. The first five appear in the bottom bar. */
enum class Destination(
    val route: String,
    val label: String,
    val labelKey: String,
    val icon: ImageVector,
    val inBottomBar: Boolean
) {
    DASHBOARD("dashboard", "Dashboard", "nav_dashboard", Icons.Filled.Dashboard, true),
    WEB_SCANNER("webscanner", "Web", "nav_web", Icons.Filled.TravelExplore, true),
    APK_ANALYZER("apkanalyzer", "APK", "nav_apk", Icons.Filled.Android, true),
    NETWORK_INSPECTOR("networkinspector", "Network", "nav_network", Icons.Filled.Lan, true),
    FINDINGS("findings", "Findings", "nav_findings", Icons.Filled.Shield, true),
    API_INSPECTOR("apiinspector", "API Inspector", "nav_web", Icons.Filled.Api, false),
    REPORTS("reports", "Reports", "nav_findings", Icons.Filled.Assessment, false),
    SETTINGS("settings", "Settings", "settings_title", Icons.Filled.Settings, false);

    companion object {
        val bottomBar: List<Destination> = entries.filter { it.inBottomBar }
        fun fromRoute(route: String?): Destination =
            entries.firstOrNull { it.route == route } ?: DASHBOARD
    }
}
