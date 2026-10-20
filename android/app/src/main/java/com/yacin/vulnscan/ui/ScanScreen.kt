package com.yacin.vulnscan.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import com.yacin.vulnscan.ScanViewModel
import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ReportBuilder
import com.yacin.vulnscan.scanner.ReportSharer
import com.yacin.vulnscan.scanner.Scanner
import com.yacin.vulnscan.scanner.Severity

// Friendly Arabic names for each check id.
private val checkNames = mapOf(
    "headers" to "الهيدرات الأمنية",
    "tls" to "شهادة/تشفير TLS",
    "exposure" to "ملفات مكشوفة",
    "fingerprint" to "البصمة التقنية",
    "ports" to "المنافذ المفتوحة"
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ScanScreen(vm: ScanViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(title = {
                Text("🛡️ VulnScan — فاحص الثغرات", fontWeight = FontWeight.Bold)
            })
        }
    ) { pad ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Authorization warning
            Card(colors = CardDefaults.cardColors(containerColor = Color(0x22FF9800))) {
                Text(
                    "⚠️ للفحص المُصرّح به فقط — افحص الأنظمة التي تملكها أو لديك إذن " +
                        "كتابي باختبارها. الفحص غير المصرّح به قد يكون مخالفاً للقانون.",
                    Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }

            // Step 1 — target
            StepLabel("1", "أدخل الهدف")
            OutlinedTextField(
                value = state.target,
                onValueChange = vm::onTargetChange,
                label = { Text("مثال: example.com أو https://site.com/page?id=1") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            // Step 2 — what to scan
            StepLabel("2", "اختر نوع الفحص")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = vm::selectAllChecks) { Text("تحديد الكل") }
                TextButton(onClick = vm::clearChecks) { Text("إلغاء الكل") }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Scanner.allChecks.forEach { check ->
                    FilterChip(
                        selected = check.id in state.selectedChecks,
                        onClick = { vm.toggleCheck(check.id) },
                        label = { Text(checkNames[check.id] ?: check.id) }
                    )
                }
            }

            // Step 3 — authorization
            StepLabel("3", "أكّد التفويض")
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = state.authorized, onCheckedChange = vm::onAuthorizedChange)
                Text("أؤكد أنني مخوّل لفحص هذا الهدف")
            }

            // Scan button
            Button(
                onClick = vm::startScan,
                enabled = !state.running,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(
                    if (state.running) "جارٍ الفحص…" else "ابدأ الفحص",
                    fontSize = 17.sp, fontWeight = FontWeight.Bold
                )
            }

            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }

            if (state.running) {
                val (done, total) = state.progress
                LinearProgressIndicator(
                    progress = { if (total == 0) 0f else done.toFloat() / total },
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    CircularProgressIndicator(Modifier.size(20.dp))
                    Text("$done / $total فحوصات مكتملة")
                }
            }

            if (state.completed) {
                HorizontalDivider()
                Text("النتائج", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                SummaryBar(state.findings)

                // Share actions
                ShareActions(
                    onShareReport = {
                        ReportSharer.shareText(
                            context, "تقرير فحص الثغرات",
                            ReportBuilder.markdown(state.target, state.findings)
                        )
                    },
                    onShareFile = {
                        ReportSharer.shareFile(
                            context, "vulnscan-report.md",
                            ReportBuilder.markdown(state.target, state.findings)
                        )
                    },
                    onSendToAi = {
                        ReportSharer.shareText(
                            context, "إنشاء تقرير بالذكاء الاصطناعي",
                            ReportBuilder.aiPrompt(state.target, state.findings)
                        )
                    }
                )

                Spacer(Modifier.height(4.dp))
                if (state.findings.isEmpty()) {
                    Text("لم يتم العثور على ثغرات. ✅")
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.height(420.dp)
                    ) {
                        items(state.findings) { FindingCard(it) }
                    }
                }
            }
        }
    }
}

@Composable
private fun StepLabel(number: String, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Card(colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primary)) {
            Text(
                number,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 2.dp)
            )
        }
        Text(text, fontWeight = FontWeight.Bold, fontSize = 16.sp)
    }
}

@Composable
private fun ShareActions(
    onShareReport: () -> Unit,
    onShareFile: () -> Unit,
    onSendToAi: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onSendToAi, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.SmartToy, contentDescription = null)
            Spacer(Modifier.size(8.dp))
            Text("إرسال لتطبيق ذكاء اصطناعي")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onShareReport, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Share, contentDescription = null)
                Spacer(Modifier.size(6.dp))
                Text("مشاركة")
            }
            OutlinedButton(onClick = onShareFile, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Description, contentDescription = null)
                Spacer(Modifier.size(6.dp))
                Text("كملف")
            }
        }
    }
}

@Composable
private fun SummaryBar(findings: List<Finding>) {
    val counts = Severity.values().associateWith { sev -> findings.count { it.severity == sev } }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Severity.values().forEach { sev ->
            Card(colors = CardDefaults.cardColors(containerColor = colorFor(sev).copy(alpha = 0.15f))) {
                Text(
                    "${sevLabelAr(sev)}: ${counts[sev]}",
                    color = colorFor(sev),
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Card(colors = CardDefaults.cardColors(containerColor = colorFor(f.severity))) {
                    Text(
                        sevLabelAr(f.severity), color = Color.White,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 12.sp
                    )
                }
                Text(f.title, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            }
            Spacer(Modifier.height(4.dp))
            Text("الاختبار: ${f.check}  •  ${f.target}",
                style = MaterialTheme.typography.bodySmall)
            if (f.detail.isNotEmpty())
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
            if (f.evidence.isNotEmpty()) {
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Text("الدليل: ${f.evidence}", style = MaterialTheme.typography.bodySmall)
            }
            if (f.remediation.isNotEmpty())
                Text("الإصلاح: ${f.remediation}", style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF2E7D32))
        }
    }
}

private fun sevLabelAr(sev: Severity): String = when (sev) {
    Severity.CRITICAL -> "حرجة"
    Severity.HIGH -> "عالية"
    Severity.MEDIUM -> "متوسطة"
    Severity.LOW -> "منخفضة"
    Severity.INFO -> "معلومة"
}

private fun colorFor(sev: Severity): Color = when (sev) {
    Severity.CRITICAL -> Color(0xFFB00020)
    Severity.HIGH -> Color(0xFFD32F2F)
    Severity.MEDIUM -> Color(0xFFF57C00)
    Severity.LOW -> Color(0xFF1976D2)
    Severity.INFO -> Color(0xFF616161)
}
