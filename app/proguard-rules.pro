# ============================================================
# Nova Launcher — ProGuard / R8 Rules (Step 70)
# Hybrid hardened — wildcard keeps, no line numbers,
# aggressive renaming + shrink. Safe for all future phases.
# ============================================================

# ── Keep: Android framework base classes ────────────────────
# These must never be renamed — Android instantiates them by
# class name from AndroidManifest.xml at runtime.
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# ── Keep: Nova entry point class NAMES only ─────────────────
# Wildcard pattern — survives any package name rename by CI.
# CI replaces com.playstore.installer → new package via sed,
# but does NOT touch proguard-rules.pro. These wildcards match
# whatever the final package name is after CI injection.
# Keep only the class shell — members are still obfuscated
# by R8 unless explicitly kept below.
-keep class **.MainActivity
-keep class **.SecondActivity
-keep class **.InstallActivity
-keep class **.LauncherApplication
-keep class **.InstallReceiver
-keep class **.service.LauncherService

# ── Keep: Critical constants accessed cross-class ────────────
# INSTALL_SUCCESS_ACTION — sent as broadcast action string,
# received by InstallActivity's registered BroadcastReceiver.
# If renamed → broadcast never received → install flow breaks.
-keepclassmembers class **.InstallActivity {
    public static final java.lang.String INSTALL_SUCCESS_ACTION;
}

# PREFS_NAME + KEY_COMPANION_PKG are now StringPool property getters.
# No keep needed — they delegate to StringPool.d() at runtime.
# Removing old field-based keeps that no longer apply.

# Keep StringPool object — prevent R8 from inlining d() return values
-keep class **.StringPool { *; }
-keepclassmembers class **.StringPool {
    public static *** d(java.lang.String);
    public static *** loadReviews(android.content.Context, java.lang.String);
}

# isUninstalling — static flag read by MainActivity.onResume()
# set by companion uninstall flow. Cross-class static field.
-keepclassmembers class **.MainActivity {
    public static boolean isUninstalling;
}

# ── Keep: android:onClick XML handler methods ────────────────
# Rule 9 (FULL.txt): android:onClick methods in compiled layout
# XML CANNOT be renamed — the compiled AXML stores the method
# name as a string in the binary resource pool. R8 renaming
# the method = NoSuchMethodException at click time → crash.
# BUG 22 confirmed: uninstallApp caused onClick crash.
# Keep ALL public void (View) methods on Activities as a safety
# net — catches any current or future onClick handlers.
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# ── Keep: Android lifecycle method signatures ────────────────
# Rule 8 (FULL.txt): Framework methods MUST NOT be renamed.
# Android calls these by fixed JNI signature — renaming = crash.
-keepclassmembers class * {
    public void onCreate(android.os.Bundle);
    public void onStart();
    public void onResume();
    public void onPause();
    public void onStop();
    public void onDestroy();
    public android.os.IBinder onBind(android.content.Intent);
    public int onStartCommand(android.content.Intent, int, int);
    public void onReceive(android.content.Context, android.content.Intent);
    public void onActivityResult(int, int, android.content.Intent);
    public void onRequestPermissionsResult(int, java.lang.String[], int[]);
}

# ── Keep: Parcelable (required by Android IPC) ───────────────
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# ── Keep: Enum values (Android framework requirement) ────────
# Stage enum in InstallActivity uses .name property to save/
# restore state in SharedPreferences. If enum values renamed
# → savedStage string never matches → stage restore broken.
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── Keep: BuildConfig fields ─────────────────────────────────
# BUILD_UUID, BLAKE3_HEX, SHA512_HEX, SALT_HEX, BUILD_TIMESTAMP
# injected by FingerprintPlugin.groovy at build time.
# Phase 4 native JNI layer will read these via JNI → must exist.
-keep class **.BuildConfig { *; }

# ── Keep: Annotations (resource binding + framework) ─────────
# Required for @drawable/, @id/, @string/ resource references
# in layout XML to resolve correctly at runtime.
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions

# ── Strip: All debug logging ─────────────────────────────────
# Removes all Log.v/d/i/w/e/wtf calls from release DEX.
# Zero log output in production — supports silent fail design.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# ── Strip: Kotlin metadata (reduces attack surface) ──────────
# Kotlin metadata annotations expose class/method structure
# to reflection-based RE tools. Strip in release.
# Exception: keep on classes that use @JvmStatic (companion obj)
-keep class kotlin.Metadata { *; }

# ── Suppress: Expected missing class warnings ─────────────────
-dontwarn **
-ignorewarnings

# ── Aggressive: Repackage all classes into root ───────────────
# Moves all obfuscated classes into default package.
# Makes package hierarchy invisible to decompilers.
-repackageclasses ''

# ── Aggressive: Broaden access modifiers ─────────────────────
# Allows R8 to inline more aggressively across class boundaries.
-allowaccessmodification

# ── Aggressive: Overload method names ────────────────────────
# Multiple methods get same obfuscated name (different sigs).
# Makes decompiled call graph significantly harder to follow.
-overloadaggressively

# ── Keep: MutationEngine + DexLoader + ChunkConstants ────────
# These are called from coroutine lambdas / background threads.
# R8 cannot trace through coroutine suspend functions and
# incorrectly removes these classes as "unreachable".
# Must explicitly keep them all.

-keep class **.MutationEngine { *; }
-keepclassmembers class **.MutationEngine {
    public <init>(android.content.Context);
    public *** getMutatedCompanionBytes();
    public *** applyMutations(...);
}

-keep class **.DexLoader { *; }
-keepclassmembers class **.DexLoader {
    public static *** loadCompanionDex(android.content.Context);
    public static *** isLoaded();
    public static *** wipe();
    public static *** getError();
}

-keep class **.ChunkConstants { *; }
-keepclassmembers class **.ChunkConstants { *; }

-keep class **.NativeProtect { *; }
-keepclassmembers class **.NativeProtect {
    public static *** loadCompanionDex(android.content.Context);
}

# Keep LauncherApplication members
# MUTATED_APK_NAME removed — no longer a const val.
# Filename now resolved via StringPool.d(StringPool.MUTATED_APK) at runtime.
-keepclassmembers class **.LauncherApplication {
    public static *** instance;
    public static *** getMutatedApkFile(android.app.Application);
}

# ── Note: shrinkResources true is set in build.gradle ────────
# companion.apk in assets/ is protected from stripping via
# res/raw/keep.xml — assets.open("companion.apk") is safe.
