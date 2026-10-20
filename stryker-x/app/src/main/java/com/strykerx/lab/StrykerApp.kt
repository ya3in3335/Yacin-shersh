package com.strykerx.lab

import android.app.Application
import com.strykerx.lab.di.AppContainer

class StrykerApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}
