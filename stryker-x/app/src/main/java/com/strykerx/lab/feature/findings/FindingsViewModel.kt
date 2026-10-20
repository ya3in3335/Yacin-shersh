package com.strykerx.lab.feature.findings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.FindingEntity
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

class FindingsViewModel(
    private val repository: StrykerRepository
) : ViewModel() {

    val findings: StateFlow<List<FindingEntity>> =
        repository.allFindings.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList()
        )
}
