package com.strykerx.lab.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.common.SettingsStore
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.resources.ResourceProfile
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class SettingsViewModel(
    private val settings: SettingsStore,
    private val repository: StrykerRepository
) : ViewModel() {

    val profile: StateFlow<ResourceProfile> = settings.profile

    fun selectProfile(profile: ResourceProfile) = settings.setProfile(profile)

    fun clearHistory() {
        viewModelScope.launch { repository.clearHistory() }
    }
}
