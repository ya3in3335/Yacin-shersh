package com.yacin.vulnscan.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.yacin.vulnscan.ScanViewModel
import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.Scanner
import com.yacin.vulnscan.scanner.Severity

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ScanScreen(vm: ScanViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()

    Scaffold(topBar = { TopAppBar(title = { Text("VulnScan — automated scanner") }) }) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0x22FF9800))) {
                Text(
                    "Authorized testing only. Scan systems you own or have written " +
                        "permission to test. Unauthorized scanning may be illegal.",
                    Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }

            OutlinedTextField(
                value = state.target,
                onValueChange = vm::onTargetChange,
                label = { Text("Target (e.g. https://example.com/app?id=1)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Scanner.allChecks.forEach { check ->
                    FilterChip(
                        selected = check.id in state.selectedChecks,
                        onClick = { vm.toggleCheck(check.id) },
                        label = { Text(check.id) }
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = state.authorized, onCheckedChange = vm::onAuthorizedChange)
                Text("I am authorized to scan this target")
            }

            Button(
                onClick = vm::startScan,
                enabled = !state.running,
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (state.running) "Scanning…" else "Start scan") }

            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }

            if (state.running) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.height(24.dp))
                    Text("${state.progress.first}/${state.progress.second} checks")
                }
            }

            if (state.completed) {
                SummaryBar(state.findings)
                Spacer(Modifier.height(4.dp))
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(state.findings) { FindingCard(it) }
                    if (state.findings.isEmpty()) {
                        item { Text("No findings.") }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryBar(findings: List<Finding>) {
    val counts = Severity.values().associateWith { sev -> findings.count { it.severity == sev } }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Severity.values().forEach { sev ->
            Text("${sev.label}: ${counts[sev]}", color = colorFor(sev),
                fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("[${f.severity.label}] ${f.title}",
                color = colorFor(f.severity), fontWeight = FontWeight.Bold)
            Text("check: ${f.check}  •  ${f.target}",
                style = MaterialTheme.typography.bodySmall)
            if (f.detail.isNotEmpty()) Text(f.detail, style = MaterialTheme.typography.bodySmall)
            if (f.evidence.isNotEmpty()) {
                Divider(Modifier.padding(vertical = 4.dp))
                Text("evidence: ${f.evidence}", style = MaterialTheme.typography.bodySmall)
            }
            if (f.remediation.isNotEmpty()) {
                Text("fix: ${f.remediation}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun colorFor(sev: Severity): Color = when (sev) {
    Severity.CRITICAL -> Color(0xFFB00020)
    Severity.HIGH -> Color(0xFFD32F2F)
    Severity.MEDIUM -> Color(0xFFF57C00)
    Severity.LOW -> Color(0xFF1976D2)
    Severity.INFO -> Color(0xFF616161)
}
