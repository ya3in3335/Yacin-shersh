package com.strykerx.lab.di

import android.content.Context
import com.strykerx.lab.core.common.SettingsStore
import com.strykerx.lab.core.common.StrykerRepository
import com.strykerx.lab.core.database.StrykerDatabase
import com.strykerx.lab.core.resources.ResourceMonitor
import com.strykerx.lab.scanner.apk.ApkScanOrchestrator
import com.strykerx.lab.scanner.orchestrator.WebScanOrchestrator

/**
 * Manual dependency container. A deliberately simple alternative to a DI
 * framework — constructed once by [com.strykerx.lab.StrykerApp].
 */
class AppContainer(context: Context) {

    private val database = StrykerDatabase.get(context)

    val resourceMonitor = ResourceMonitor(context.applicationContext)

    val settings = SettingsStore(context)

    val repository = StrykerRepository(
        scanSessionDao = database.scanSessionDao(),
        findingDao = database.findingDao()
    )

    val webScanOrchestrator = WebScanOrchestrator(
        targetDao = database.targetDao(),
        scopeDao = database.scopeDao(),
        sessionDao = database.scanSessionDao(),
        findingDao = database.findingDao(),
        errorLogDao = database.errorLogDao(),
        resourceMonitor = resourceMonitor
    )

    val apkScanOrchestrator = ApkScanOrchestrator(
        appContext = context.applicationContext,
        targetDao = database.targetDao(),
        sessionDao = database.scanSessionDao(),
        findingDao = database.findingDao(),
        errorLogDao = database.errorLogDao()
    )
}
