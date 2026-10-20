package com.strykerx.lab.feature.webscanner

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
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strykerx.lab.core.common.SecurityScore
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.core.i18n.AppLanguage
import com.strykerx.lab.core.i18n.LocalAppLanguage
import com.strykerx.lab.core.i18n.t
import com.strykerx.lab.core.ui.components.FindingCard
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.core.ui.theme.SevCritical
import com.strykerx.lab.core.ui.theme.SevMedium
import com.strykerx.lab.core.ui.theme.TealGlow
import com.strykerx.lab.feature.reports.ReportBuilder
import com.strykerx.lab.feature.reports.ReportSharer
import com.strykerx.lab.di.StrykerViewModelFactory

@Composable
fun WebScannerScreen(factory: StrykerViewModelFactory) {
    val vm: WebScannerViewModel = viewModel(factory = factory)
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val lang = LocalAppLanguage.current

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ScreenHeader(t("web_title", lang), t("web_subtitle", lang))

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Text(
                t("web_authz_notice", lang),
                Modifier.padding(12.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
            )
        }

        OutlinedTextField(
            value = state.target, onValueChange = vm::onTarget,
            label = { Text(t("web_target", lang)) },
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = state.allowlist, onValueChange = vm::onAllowlist,
            label = { Text(t("web_allowlist", lang)) },
            modifier = Modifier.fillMaxWidth()
        )

        CheckRow(t("web_authorized", lang), state.authorized, vm::onAuthorized)
        CheckRow(t("web_active_tests", lang), state.allowActiveTests, vm::onActiveTests)
        CheckRow(t("web_internal", lang), state.allowInternalNetwork, vm::onInternalNetwork)

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = vm::start, enabled = !state.running,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.PlayArrow, null); Text(" " + t("web_start", lang), fontWeight = FontWeight.Bold)
            }
            OutlinedButton(
                onClick = vm::stop, enabled = state.running, modifier = Modifier.weight(1f)
            ) { Icon(Icons.Filled.Stop, null); Text(" " + t("web_stop", lang)) }
        }

        state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

        if (state.running) {
            val (done, total) = state.progress
            LinearProgressIndicator(
                progress = { if (total == 0) 0f else done.toFloat() / total },
                modifier = Modifier.fillMaxWidth()
            )
            Text("$done / $total checks", color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp)
        }

        state.message?.let {
            Text(it, color = MaterialTheme.colorScheme.secondary, fontSize = 13.sp)
        }

        if (!state.running && state.sessionId != null) {
            SecurityScoreCard(state.findings, lang)
        }

        if (state.findings.isNotEmpty()) {
            Button(
                onClick = {
                    ReportSharer.shareText(
                        context, "AI security report",
                        ReportBuilder.aiPrompt(state.target, state.findings)
                    )
                },
                modifier = Modifier.fillMaxWidth()
            ) { Icon(Icons.Filled.SmartToy, null); Text("  " + t("web_send_ai", lang)) }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        ReportSharer.shareText(context, "Security report",
                            ReportBuilder.markdown(state.target, state.findings))
                    },
                    modifier = Modifier.weight(1f)
                ) { Text(t("web_share", lang)) }
                OutlinedButton(
                    onClick = {
                        ReportSharer.shareFile(context, "cherlogons-report.md",
                            ReportBuilder.markdown(state.target, state.findings))
                    },
                    modifier = Modifier.weight(1f)
                ) { Text(t("web_export", lang)) }
            }

            state.findings.forEach { f ->
                FindingCard(
                    severity = f.severity, title = f.title, check = f.findingCode,
                    affected = f.affected, evidence = f.evidence,
                    verification = f.verificationStatus, remediation = f.remediation
                )
            }
        }
    }
}

@Composable
private fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label, color = MaterialTheme.colorScheme.onSurface, fontSize = 14.sp)
    }
}

@Composable
private fun SecurityScoreCard(findings: List<FindingEntity>, lang: AppLanguage) {
    val result = SecurityScore.fromFindings(findings)
    val color = when {
        result.percent >= 50 -> TealGlow
        result.percent >= 0 -> SevMedium
        else -> SevCritical
    }
    val sign = if (result.percent > 0) "+" else ""
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("$sign${result.percent}%", color = color,
                fontWeight = FontWeight.Bold, fontSize = 34.sp)
            Column {
                Text(t("score_title", lang), color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 13.sp)
                Text(t(result.gradeKey, lang), color = color,
                    fontWeight = FontWeight.Bold, fontSize = 18.sp)
            }
        }
    }
}
