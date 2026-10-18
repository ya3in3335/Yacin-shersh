package com.strykerx.lab.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strykerx.lab.core.i18n.AppLanguage
import com.strykerx.lab.core.i18n.LocalAppLanguage
import com.strykerx.lab.core.i18n.t
import com.strykerx.lab.core.resources.ResourceProfile
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.di.StrykerViewModelFactory

@Composable
fun SettingsScreen(factory: StrykerViewModelFactory) {
    val vm: SettingsViewModel = viewModel(factory = factory)
    val profile by vm.profile.collectAsStateWithLifecycle()
    val language by vm.language.collectAsStateWithLifecycle()
    val lang = LocalAppLanguage.current

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        ScreenHeader(t("settings_title", lang))

        // Language center
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(t("settings_language", lang), color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold)
                FlowRow(
                    Modifier.padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    AppLanguage.entries.forEach { l ->
                        FilterChip(
                            selected = l == language,
                            onClick = { vm.selectLanguage(l) },
                            label = { Text(l.nativeName) }
                        )
                    }
                }
            }
        }

        // Resource profile
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(t("settings_profile", lang), color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold)
                ResourceProfile.entries.forEach { p ->
                    ProfileRow(p, selected = p == profile, onSelect = { vm.selectProfile(p) })
                }
            }
        }

        OutlinedButton(onClick = vm::clearHistory, modifier = Modifier.fillMaxWidth()) {
            Text(t("settings_delete", lang))
        }

        Text(t("settings_about", lang),
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
    }
}

@Composable
private fun ProfileRow(profile: ResourceProfile, selected: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected = selected, onClick = onSelect)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Column(Modifier.padding(start = 4.dp)) {
            Text(
                profile.displayName + if (profile.requiresConfirmation) " (confirmation required)" else "",
                color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Medium
            )
            Text(
                "${profile.analysisWorkers} worker(s) • ${profile.maxConnections} connection(s) • " +
                    "pause < ${profile.batteryPausePercent}% battery",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
            )
        }
    }
}
