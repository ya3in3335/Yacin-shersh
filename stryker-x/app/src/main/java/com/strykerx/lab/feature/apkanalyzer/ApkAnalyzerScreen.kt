package com.strykerx.lab.feature.apkanalyzer

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strykerx.lab.core.ui.components.FindingCard
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.di.StrykerViewModelFactory

@Composable
fun ApkAnalyzerScreen(factory: StrykerViewModelFactory) {
    val vm: ApkAnalyzerViewModel = viewModel(factory = factory)
    val state by vm.state.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let(vm::analyze) }

    Column(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ScreenHeader("APK Analyzer", "Offline static analysis — the app is never executed")

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "*/*")) },
                enabled = !state.analyzing,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.Android, contentDescription = null)
                Text("  Import file", fontWeight = FontWeight.Bold)
            }
            OutlinedButton(
                onClick = vm::loadInstalledApps,
                enabled = !state.analyzing && !state.loadingApps,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.PhoneAndroid, contentDescription = null)
                Text("  Installed apps", fontWeight = FontWeight.Bold)
            }
        }

        if (state.analyzing || state.loadingApps) {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                CircularProgressIndicator(Modifier.size(22.dp))
                Text(if (state.analyzing) "Analyzing…" else "Loading installed apps…",
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            }
        }

        // Installed-apps picker (shown until a scan runs).
        if (state.installedApps.isNotEmpty() && state.report == null && !state.analyzing) {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                label = { Text("Search apps (${state.installedApps.size})") },
                singleLine = true, modifier = Modifier.fillMaxWidth()
            )
            val filtered = state.installedApps.filter {
                query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true)
            }
            LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                items(filtered) { app ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable { vm.analyzeInstalled(app) },
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text(app.label + if (app.isSystem) "  · system" else "",
                                color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Medium)
                            Text(app.packageName, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontSize = 12.sp)
                        }
                    }
                }
            }
            return@Column
        }

        state.report?.takeIf { it.ok }?.let { r ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(r.packageName, color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Text("v${r.versionName} (${r.versionCode}) • minSdk ${r.minSdk} • targetSdk ${r.targetSdk}",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                    Text("${r.permissionCount} permission(s) • ${r.componentCount} component(s)",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
            }
        }

        state.message?.let {
            Text(it, color = MaterialTheme.colorScheme.secondary, fontSize = 13.sp)
        }

        if (state.findings.isEmpty() && state.report?.ok == true) {
            Text("No static findings — the package looks clean on the checks performed.",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
        }

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(state.findings) { f ->
                FindingCard(
                    severity = f.severity, title = f.title, check = f.findingCode,
                    affected = f.affected, evidence = f.evidence,
                    verification = f.verificationStatus, remediation = f.remediation
                )
            }
        }
    }
}
