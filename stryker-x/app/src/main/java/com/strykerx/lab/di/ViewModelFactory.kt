package com.strykerx.lab.di

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.strykerx.lab.feature.dashboard.DashboardViewModel
import com.strykerx.lab.feature.settings.SettingsViewModel

/** Builds ViewModels with the [AppContainer]'s dependencies. */
class StrykerViewModelFactory(private val container: AppContainer) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T = when {
        modelClass.isAssignableFrom(DashboardViewModel::class.java) ->
            DashboardViewModel(container.repository, container.resourceMonitor) as T
        modelClass.isAssignableFrom(SettingsViewModel::class.java) ->
            SettingsViewModel(container.settings, container.repository) as T
        else -> throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
    }
}
