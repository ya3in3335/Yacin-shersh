package com.strykerx.lab.feature.dashboard

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strykerx.lab.R
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.i18n.LocalAppLanguage
import com.strykerx.lab.core.i18n.t
import com.strykerx.lab.core.resources.DeviceStatus
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.core.ui.components.StatCard
import com.strykerx.lab.core.ui.theme.SevCritical
import com.strykerx.lab.core.ui.theme.SevHigh
import com.strykerx.lab.core.ui.theme.SevInfo
import com.strykerx.lab.core.ui.theme.SevLow
import com.strykerx.lab.core.ui.theme.SevMedium
import com.strykerx.lab.di.StrykerViewModelFactory
import com.strykerx.lab.navigation.Destination

@Composable
fun DashboardScreen(
    factory: StrykerViewModelFactory,
    onNavigate: (Destination) -> Unit
) {
    val vm: DashboardViewModel = viewModel(factory = factory)
    val state by vm.state.collectAsStateWithLifecycle()
    val lang = LocalAppLanguage.current

    LaunchedEffect(Unit) { vm.refreshDeviceStatus() }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Image(
                painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = "Cherlogons logo",
                modifier = Modifier.size(48.dp)
            )
            ScreenHeader("Cherlogons", t("app_subtitle", lang))
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(t("dash_completed", lang), state.completedScans.toString(), Modifier.weight(1f))
            StatCard(t("dash_active", lang), state.activeScans.toString(), Modifier.weight(1f),
                accent = MaterialTheme.colorScheme.secondary)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(t("dash_potential", lang), state.potentialFindings.toString(), Modifier.weight(1f),
                accent = SevMedium)
            StatCard(t("dash_confirmed", lang), state.confirmedFindings.toString(), Modifier.weight(1f),
                accent = SevCritical)
        }

        SeverityDistribution(state)
        DeviceStatusCard(state.device)
        RecentActivityCard(state)

        Button(
            onClick = { onNavigate(Destination.WEB_SCANNER) },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.PlayArrow, contentDescription = null)
            Text("  " + t("dash_quickstart", lang), fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun SeverityDistribution(state: DashboardUiState) {
    val lang = LocalAppLanguage.current
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(t("dash_severity", lang), color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold)
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                SevPill("C", state.severity.critical, SevCritical)
                SevPill("H", state.severity.high, SevHigh)
                SevPill("M", state.severity.medium, SevMedium)
                SevPill("L", state.severity.low, SevLow)
                SevPill("I", state.severity.info, SevInfo)
            }
        }
    }
}

@Composable
private fun SevPill(label: String, count: Int, color: Color) {
    Column {
        Text(count.toString(), color = color, fontWeight = FontWeight.Bold, fontSize = 20.sp)
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
    }
}

@Composable
private fun DeviceStatusCard(device: DeviceStatus) {
    val lang = LocalAppLanguage.current
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(t("dash_device", lang), color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold)
            Text(
                "Battery: ${device.batteryPercent}%" +
                    (if (device.isCharging) " (charging)" else "") +
                    "   •   Thermal: ${device.thermal.label}" +
                    (if (device.lowStorage) "   •   Low storage" else ""),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 6.dp)
            )
        }
    }
}

@Composable
private fun RecentActivityCard(state: DashboardUiState) {
    val lang = LocalAppLanguage.current
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(t("dash_recent", lang), color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold)
            if (state.recent.isEmpty()) {
                Text(t("dash_no_scans", lang), color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
            } else {
                state.recent.take(5).forEach { s ->
                    Text("• ${s.state} — ${s.completedChecks}/${s.totalChecks} checks",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
                }
            }
        }
    }
}
