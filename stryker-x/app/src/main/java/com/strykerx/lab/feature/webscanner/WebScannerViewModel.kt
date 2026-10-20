package com.strykerx.lab.feature.webscanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.common.SettingsStore
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.FindingEntity
import com.strykerx.lab.scanner.orchestrator.WebScanOrchestrator
import com.strykerx.lab.scanner.orchestrator.WebScanRequest
import com.strykerx.lab.scanner.web.ScopeValidator
import com.strykerx.lab.scanner.web.ScopeResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

data class WebScanUiState(
    val target: String = "",
    val allowlist: String = "",
    val authorized: Boolean = false,
    val allowActiveTests: Boolean = false,
    val allowInternalNetwork: Boolean = false,
    val running: Boolean = false,
    val progress: Pair<Int, Int> = 0 to 0,
    val message: String? = null,
    val error: String? = null,
    val sessionId: String? = null,
    val findings: List<FindingEntity> = emptyList()
)

class WebScannerViewModel(
    private val orchestrator: WebScanOrchestrator,
    private val settings: SettingsStore,
    private val repository: StrykerRepository
) : ViewModel() {

    private val _state = MutableStateFlow(WebScanUiState())
    val state: StateFlow<WebScanUiState> = _state.asStateFlow()

    private var scanJob: Job? = null
    private var findingsJob: Job? = null

    fun onTarget(v: String) { _state.value = _state.value.copy(target = v, error = null) }
    fun onAllowlist(v: String) { _state.value = _state.value.copy(allowlist = v) }
    fun onAuthorized(v: Boolean) { _state.value = _state.value.copy(authorized = v) }
    fun onActiveTests(v: Boolean) { _state.value = _state.value.copy(allowActiveTests = v) }
    fun onInternalNetwork(v: Boolean) { _state.value = _state.value.copy(allowInternalNetwork = v) }

    fun start() {
        val s = _state.value
        if (s.running) return
        if (ScopeValidator.validateSyntax(s.target) is ScopeResult.Rejected) {
            _state.value = s.copy(error = "Enter a valid http(s) URL or host."); return
        }
        if (!s.authorized) {
            _state.value = s.copy(error = "Confirm you are authorized to scan this target."); return
        }

        val allow = s.allowlist.split("\n", ",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val request = WebScanRequest(
            targetUrl = s.target,
            allowlist = allow,
            authorizationDeclared = s.authorized,
            allowActiveTests = s.allowActiveTests,
            allowInternalNetwork = s.allowInternalNetwork
        )
        _state.value = s.copy(running = true, error = null, message = null,
            findings = emptyList(), progress = 0 to 0)

        scanJob = viewModelScope.launch {
            val outcome = orchestrator.run(request, settings.profile.value) { done, total ->
                _state.value = _state.value.copy(progress = done to total)
            }
            observeFindings(outcome.sessionId)
            _state.value = _state.value.copy(
                running = false,
                sessionId = outcome.sessionId,
                message = outcome.message
            )
        }
    }

    fun stop() {
        scanJob?.cancel()
        scanJob = null
        _state.value = _state.value.copy(running = false, message = "Scan stopped.")
    }

    private fun observeFindings(sessionId: String) {
        findingsJob?.cancel()
        findingsJob = viewModelScope.launch {
            repository.findingsForSession(sessionId).collectLatest { list ->
                _state.value = _state.value.copy(findings = list)
            }
        }
    }

    override fun onCleared() {
        scanJob?.cancel()
        findingsJob?.cancel()
    }
}
