package com.yacin.vulnscan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.Scanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ScanUiState(
    val target: String = "",
    val authorized: Boolean = false,
    val selectedChecks: Set<String> = Scanner.allChecks.map { it.id }.toSet(),
    val running: Boolean = false,
    val progress: Pair<Int, Int> = 0 to 0,
    val findings: List<Finding> = emptyList(),
    val error: String? = null,
    val completed: Boolean = false
)

class ScanViewModel : ViewModel() {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    fun onTargetChange(value: String) {
        _state.value = _state.value.copy(target = value, error = null)
    }

    fun onAuthorizedChange(value: Boolean) {
        _state.value = _state.value.copy(authorized = value)
    }

    fun toggleCheck(id: String) {
        val current = _state.value.selectedChecks.toMutableSet()
        if (id in current) current.remove(id) else current.add(id)
        _state.value = _state.value.copy(selectedChecks = current)
    }

    fun startScan() {
        val s = _state.value
        if (s.target.isBlank()) {
            _state.value = s.copy(error = "Enter a target URL or host.")
            return
        }
        if (!s.authorized) {
            _state.value = s.copy(error = "Confirm you are authorized to scan this target.")
            return
        }
        if (s.selectedChecks.isEmpty()) {
            _state.value = s.copy(error = "Select at least one check.")
            return
        }
        _state.value = s.copy(running = true, findings = emptyList(),
            completed = false, error = null, progress = 0 to s.selectedChecks.size)

        viewModelScope.launch {
            val results = withContext(Dispatchers.IO) {
                Scanner.scan(s.target, s.selectedChecks) { done, total ->
                    _state.value = _state.value.copy(progress = done to total)
                }
            }
            _state.value = _state.value.copy(
                running = false, findings = results, completed = true
            )
        }
    }
}
