package com.strykerx.lab.feature.apkanalyzer

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.scanner.apk.ApkReport
import com.strykerx.lab.scanner.apk.ApkScanOrchestrator
import com.strykerx.lab.scanner.apk.ApkScanOutcome
import com.strykerx.lab.scanner.apk.InstalledApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

data class ApkUiState(
    val analyzing: Boolean = false,
    val loadingApps: Boolean = false,
    val installedApps: List<InstalledApp> = emptyList(),
    val report: ApkReport? = null,
    val findings: List<FindingEntity> = emptyList(),
    val message: String? = null,
    val sessionId: String? = null
)

class ApkAnalyzerViewModel(
    private val orchestrator: ApkScanOrchestrator,
    private val repository: StrykerRepository
) : ViewModel() {

    private val _state = MutableStateFlow(ApkUiState())
    val state: StateFlow<ApkUiState> = _state.asStateFlow()

    fun analyze(uri: Uri) = runScan { orchestrator.analyze(uri) }

    fun analyzeInstalled(app: InstalledApp) = runScan { orchestrator.analyzeInstalled(app.sourceDir) }

    fun loadInstalledApps() {
        if (_state.value.loadingApps || _state.value.installedApps.isNotEmpty()) return
        _state.value = _state.value.copy(loadingApps = true)
        viewModelScope.launch {
            val apps = orchestrator.installedApps()
            _state.value = _state.value.copy(loadingApps = false, installedApps = apps)
        }
    }

    private fun runScan(block: suspend () -> ApkScanOutcome) {
        if (_state.value.analyzing) return
        _state.value = _state.value.copy(
            analyzing = true, message = null, report = null, findings = emptyList(), sessionId = null
        )
        viewModelScope.launch {
            val outcome = block()
            _state.value = _state.value.copy(
                analyzing = false,
                report = outcome.report,
                message = outcome.message,
                sessionId = outcome.sessionId
            )
            outcome.sessionId?.let { sid ->
                launch {
                    repository.findingsForSession(sid).collectLatest { list ->
                        _state.value = _state.value.copy(findings = list)
                    }
                }
            }
        }
    }
}
