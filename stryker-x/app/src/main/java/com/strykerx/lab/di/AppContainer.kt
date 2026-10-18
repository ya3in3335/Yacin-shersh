package com.strykerx.lab.di

import android.content.Context
import com.strykerx.lab.core.common.SettingsStore
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.StrykerDatabase
import com.strykerx.lab.core.resources.ResourceMonitor

/**
 * Manual dependency container. A deliberately simple alternative to a DI
 * framework for Phase A — constructed once by [com.strykerx.lab.StrykerApp].
 */
class AppContainer(context: Context) {

    private val database = StrykerDatabase.get(context)

    val repository = StrykerRepository(
        scanSessionDao = database.scanSessionDao(),
        findingDao = database.findingDao()
    )

    val resourceMonitor = ResourceMonitor(context.applicationContext)

    val settings = SettingsStore(context)
}
