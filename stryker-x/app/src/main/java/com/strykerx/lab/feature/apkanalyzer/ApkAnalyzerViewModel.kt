package com.strykerx.lab.feature.apkanalyzer

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.scanner.apk.ApkReport
import com.strykerx.lab.scanner.apk.ApkScanOrchestrator
import com.strykerx.lab.core.common.StrykerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

data class ApkUiState(
    val analyzing: Boolean = false,
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

    fun analyze(uri: Uri) {
        if (_state.value.analyzing) return
        _state.value = ApkUiState(analyzing = true, message = null)
        viewModelScope.launch {
            val outcome = orchestrator.analyze(uri)
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
