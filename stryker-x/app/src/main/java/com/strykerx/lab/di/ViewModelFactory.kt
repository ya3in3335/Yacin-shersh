package com.strykerx.lab.di

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.strykerx.lab.feature.apkanalyzer.ApkAnalyzerViewModel
import com.strykerx.lab.feature.dashboard.DashboardViewModel
import com.strykerx.lab.feature.findings.FindingsViewModel
import com.strykerx.lab.feature.settings.SettingsViewModel
import com.strykerx.lab.feature.webscanner.WebScannerViewModel

/** Builds ViewModels with the [AppContainer]'s dependencies. */
class StrykerViewModelFactory(private val container: AppContainer) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T = when {
        modelClass.isAssignableFrom(DashboardViewModel::class.java) ->
            DashboardViewModel(container.repository, container.resourceMonitor) as T
        modelClass.isAssignableFrom(SettingsViewModel::class.java) ->
            SettingsViewModel(container.settings, container.repository) as T
        modelClass.isAssignableFrom(WebScannerViewModel::class.java) ->
            WebScannerViewModel(container.webScanOrchestrator, container.settings, container.repository) as T
        modelClass.isAssignableFrom(FindingsViewModel::class.java) ->
            FindingsViewModel(container.repository) as T
        modelClass.isAssignableFrom(ApkAnalyzerViewModel::class.java) ->
            ApkAnalyzerViewModel(container.apkScanOrchestrator, container.repository) as T
        else -> throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
    }
}
