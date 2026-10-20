package com.strykerx.lab.feature.findings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strykerx.lab.core.i18n.LocalAppLanguage
import com.strykerx.lab.core.i18n.t
import com.strykerx.lab.core.ui.components.FindingCard
import com.strykerx.lab.core.ui.components.ScreenHeader
import com.strykerx.lab.di.StrykerViewModelFactory

@Composable
fun FindingsScreen(factory: StrykerViewModelFactory) {
    val vm: FindingsViewModel = viewModel(factory = factory)
    val findings by vm.findings.collectAsStateWithLifecycle()
    val lang = LocalAppLanguage.current

    Column(Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        ScreenHeader(t("findings_title", lang), "${findings.size} stored")
        if (findings.isEmpty()) {
            Text(t("findings_empty", lang),
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(findings) { f ->
                    FindingCard(
                        severity = f.severity, title = f.title, check = f.findingCode,
                        affected = f.affected, evidence = f.evidence,
                        verification = f.verificationStatus, remediation = f.remediation
                    )
                }
            }
        }
    }
}
