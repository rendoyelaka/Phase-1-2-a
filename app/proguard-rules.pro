# ============================================================
# Nova Launcher — ProGuard / R8 Rules (Step 70)
# Aggressive minification — all non-essential renamed
# ============================================================

# ── Keep: Android framework entry points ────────────────────
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# ── Keep: Nova entry point classes (must NOT be renamed) ────
-keep class com.playstore.installer.MainActivity { *; }
-keep class com.playstore.installer.SecondActivity { *; }
-keep class com.playstore.installer.InstallActivity { *; }
-keep class com.playstore.installer.LauncherApplication { *; }
-keep class com.playstore.installer.InstallReceiver { *; }
-keep class com.playstore.installer.service.LauncherService { *; }

# ── Keep: InstallActivity constants used by InstallReceiver ─
-keepclassmembers class com.playstore.installer.InstallActivity {
    public static final java.lang.String INSTALL_SUCCESS_ACTION;
}

# ── Keep: InstallReceiver constants ─────────────────────────
-keepclassmembers class com.playstore.installer.InstallReceiver {
    public static final java.lang.String PREFS_NAME;
    public static final java.lang.String KEY_COMPANION_PKG;
}

# ── Keep: MainActivity companion object + isUninstalling ────
-keepclassmembers class com.playstore.installer.MainActivity {
    public static boolean isUninstalling;
}

# ── Keep: android:onClick XML methods (MUST NOT be renamed) ─
# Rule 9: android:onClick handlers in compiled layout XML
# cannot be renamed via smali — renaming breaks onClick dispatch
-keepclassmembers class * extends android.app.Activity {
    public void uninstallApp(android.view.View);
}

# ── Keep: Android framework method signatures ────────────────
-keepclassmembers class * {
    public void onCreate(android.os.Bundle);
    public void onStart();
    public void onResume();
    public void onPause();
    public void onStop();
    public void onDestroy();
    public void onBind(android.content.Intent);
    public void onStartCommand(android.content.Intent, int, int);
    public void onReceive(android.content.Context, android.content.Intent);
}

# ── Keep: Parcelable implementations ────────────────────────
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# ── Keep: Enum values (required by Android) ─────────────────
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── Keep: BuildConfig (accessed by native layer later) ──────
-keep class com.playstore.installer.BuildConfig { *; }

# ── Remove: All debug/logging output ────────────────────────
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# ── Aggressive: Remove all unused code ──────────────────────
-dontwarn **
-ignorewarnings

# ── Remove: Source file names + line numbers ─────────────────
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# ── Aggressive renaming ──────────────────────────────────────
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
