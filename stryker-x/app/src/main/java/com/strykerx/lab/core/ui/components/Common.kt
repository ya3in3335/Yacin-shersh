package com.strykerx.lab.core.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Construction
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ScreenHeader(title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        Text(
            title,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp
        )
        if (subtitle != null) {
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
        }
    }
}

@Composable
fun StatCard(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.primary
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(value, color = accent, fontWeight = FontWeight.Bold, fontSize = 26.sp)
            Text(
                label,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp
            )
        }
    }
}

@Composable
fun FindingCard(
    severity: String,
    title: String,
    check: String,
    affected: String,
    evidence: String,
    verification: String,
    remediation: String
) {
    val sev = com.strykerx.lab.core.common.Severity.from(severity)
    val color = when (sev) {
        com.strykerx.lab.core.common.Severity.CRITICAL -> com.strykerx.lab.core.ui.theme.SevCritical
        com.strykerx.lab.core.common.Severity.HIGH -> com.strykerx.lab.core.ui.theme.SevHigh
        com.strykerx.lab.core.common.Severity.MEDIUM -> com.strykerx.lab.core.ui.theme.SevMedium
        com.strykerx.lab.core.common.Severity.LOW -> com.strykerx.lab.core.ui.theme.SevLow
        com.strykerx.lab.core.common.Severity.INFO -> com.strykerx.lab.core.ui.theme.SevInfo
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("[${sev.label}] $title", color = color, fontWeight = FontWeight.Bold)
            Text("$check  •  $verification", color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp)
            Text(affected, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
            if (evidence.isNotBlank()) {
                Text("Evidence: $evidence", color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            }
            if (remediation.isNotBlank()) {
                Text("Fix: $remediation", color = MaterialTheme.colorScheme.secondary,
                    fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}

/** Placeholder for screens delivered in later phases. Honest, not fake content. */
@Composable
fun ComingSoonScreen(title: String, phase: String) {
    Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                Icons.Filled.Construction,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Text(title, color = MaterialTheme.colorScheme.onBackground,
                fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text(
                "This module is scheduled for $phase.\nIt is intentionally not yet functional — " +
                    "no simulated results are shown.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                fontSize = 13.sp
            )
        }
    }
}
