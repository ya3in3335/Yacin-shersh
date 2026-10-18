package com.strykerx.lab.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import com.strykerx.lab.core.resources.ResourceProfile
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.di.StrykerViewModelFactory

@Composable
fun SettingsScreen(factory: StrykerViewModelFactory) {
    val vm: SettingsViewModel = viewModel(factory = factory)
    val profile by vm.profile.collectAsStateWithLifecycle()

    Column(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        ScreenHeader("Settings")

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text("Resource Profile", color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold)
                Text("Controls concurrency, pacing and the battery level at which scans pause.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp,
                    modifier = Modifier.padding(bottom = 8.dp))
                ResourceProfile.entries.forEach { p ->
                    ProfileRow(p, selected = p == profile, onSelect = { vm.selectProfile(p) })
                }
            }
        }

        OutlinedButton(onClick = vm::clearHistory, modifier = Modifier.fillMaxWidth()) {
            Text("Delete Scan History & Findings")
        }

        Text(
            "STRYKER X runs 100% locally. No telemetry, no accounts, no remote backend. " +
                "For authorized security assessments only.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
        )
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
