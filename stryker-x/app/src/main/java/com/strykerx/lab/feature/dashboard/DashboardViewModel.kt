package com.strykerx.lab.feature.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.common.SeverityStats
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.ScanSessionEntity
import com.strykerx.lab.core.resources.DeviceStatus
import com.strykerx.lab.core.resources.ResourceMonitor
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

data class DashboardUiState(
    val completedScans: Int = 0,
    val activeScans: Int = 0,
    val confirmedFindings: Int = 0,
    val potentialFindings: Int = 0,
    val severity: SeverityStats = SeverityStats(),
    val recent: List<ScanSessionEntity> = emptyList(),
    val device: DeviceStatus = DeviceStatus.UNKNOWN
)

class DashboardViewModel(
    repository: StrykerRepository,
    private val resourceMonitor: ResourceMonitor
) : ViewModel() {

    val state: StateFlow<DashboardUiState> = combine(
        repository.completedScans,
        repository.activeScans,
        repository.confirmedFindings,
        repository.potentialFindings,
        combine(
            repository.severityStats,
            repository.recentSessions(),
            resourceMonitor.status
        ) { sev, recent, device -> Triple(sev, recent, device) }
    ) { completed, active, confirmed, potential, triple ->
        DashboardUiState(
            completedScans = completed,
            activeScans = active,
            confirmedFindings = confirmed,
            potentialFindings = potential,
            severity = triple.first,
            recent = triple.second,
            device = triple.third
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DashboardUiState())

    /** Sample device resources on demand (no continuous polling). */
    fun refreshDeviceStatus() {
        resourceMonitor.refresh()
    }
}
