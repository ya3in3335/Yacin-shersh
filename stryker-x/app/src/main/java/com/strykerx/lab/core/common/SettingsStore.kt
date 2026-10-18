package com.strykerx.lab.core.common

import android.content.Context
import com.strykerx.lab.core.resources.ResourceProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Lightweight persisted settings (SharedPreferences). Kept minimal on purpose —
 * no secrets are stored here.
 */
class SettingsStore(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences("stryker_settings", Context.MODE_PRIVATE)

    private val _profile = MutableStateFlow(
        ResourceProfile.from(prefs.getString(KEY_PROFILE, null))
    )
    val profile: StateFlow<ResourceProfile> = _profile.asStateFlow()

    fun setProfile(profile: ResourceProfile) {
        prefs.edit().putString(KEY_PROFILE, profile.name).apply()
        _profile.value = profile
    }

    private companion object {
        const val KEY_PROFILE = "resource_profile"
    }
}
