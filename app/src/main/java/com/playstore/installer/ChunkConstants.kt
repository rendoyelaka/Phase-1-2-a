package com.playstore.installer

/**
 * ChunkConstants — PLACEHOLDER
 * This file is overwritten by scripts/chunk_constants_gen.py during CI build.
 * The real file contains per-build XOR-masked chunk offsets, sizes, and AES key.
 *
 * DO NOT EDIT — any edits will be overwritten by the build pipeline.
 * Phase 3 Step 24.
 */
internal object ChunkConstants {

    const val BUILD_UUID  = "placeholder-build-uuid"
    const val BUILD_HASH  = "placeholder00000"
    const val N_CHUNKS    = 0  // Set by CI

    private const val XK_HI = 0x0000
    private const val XK_LO = 0x0000
    val XOR_KEY: Int get() = (XK_HI shl 16) or XK_LO

    val MASKED_KEY = intArrayOf()
    val MASKED_IV  = intArrayOf()

    const val SHA512_HASH = ""
    const val SHA256_HASH = ""

    fun unmaskOffset(masked: Int): Long = (masked xor XOR_KEY).toLong() and 0xFFFFFFFFL
    fun unmaskSize(masked: Int): Int    = masked xor XOR_KEY

    fun getAesKey(): ByteArray = ByteArray(32)
    fun getAesIv():  ByteArray = ByteArray(12)

    fun getSoName(chunkIndex: Int): String = "libdatabridge.so"
    fun getMaskedOffset(chunkIndex: Int, is64bit: Boolean): Int = 0
    fun getMaskedSize(chunkIndex: Int, is64bit: Boolean): Int = 0
}
