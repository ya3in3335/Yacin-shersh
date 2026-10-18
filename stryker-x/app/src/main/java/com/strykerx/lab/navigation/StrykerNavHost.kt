package com.strykerx.lab.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.strykerx.lab.di.AppContainer
import com.strykerx.lab.di.StrykerViewModelFactory
import com.strykerx.lab.feature.apiinspector.ApiInspectorScreen
import com.strykerx.lab.feature.apkanalyzer.ApkAnalyzerScreen
import com.strykerx.lab.feature.dashboard.DashboardScreen
import com.strykerx.lab.feature.findings.FindingsScreen
import com.strykerx.lab.feature.networkinspector.NetworkInspectorScreen
import com.strykerx.lab.feature.reports.ReportsScreen
import com.strykerx.lab.feature.settings.SettingsScreen
import com.strykerx.lab.feature.webscanner.WebScannerScreen

@Composable
fun StrykerNavHost(container: AppContainer) {
    val navController = rememberNavController()
    val factory = StrykerViewModelFactory(container)

    val backStack by navController.currentBackStackEntryAsState()
    val current = Destination.fromRoute(backStack?.destination?.route)

    Scaffold(
        bottomBar = {
            NavigationBar {
                Destination.bottomBar.forEach { dest ->
                    NavigationBarItem(
                        selected = current == dest,
                        onClick = {
                            if (current != dest) {
                                navController.navigate(dest.route) {
                                    popUpTo(Destination.DASHBOARD.route) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        },
                        icon = { Icon(dest.icon, contentDescription = dest.label) },
                        label = { Text(dest.label) }
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Destination.DASHBOARD.route,
            modifier = Modifier.padding(padding)
        ) {
            composable(Destination.DASHBOARD.route) {
                DashboardScreen(
                    factory = factory,
                    onNavigate = { navController.navigate(it.route) { launchSingleTop = true } }
                )
            }
            composable(Destination.WEB_SCANNER.route) { WebScannerScreen() }
            composable(Destination.APK_ANALYZER.route) { ApkAnalyzerScreen() }
            composable(Destination.NETWORK_INSPECTOR.route) { NetworkInspectorScreen() }
            composable(Destination.FINDINGS.route) { FindingsScreen() }
            composable(Destination.API_INSPECTOR.route) { ApiInspectorScreen() }
            composable(Destination.REPORTS.route) { ReportsScreen() }
            composable(Destination.SETTINGS.route) { SettingsScreen(factory = factory) }
        }
    }
}
