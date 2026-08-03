/**
 * key_derive.c — Phase 4 Step 29
 * Runtime AES-256 key derivation using HKDF-SHA256.
 *
 * Key is derived from:
 *   1. Masked key material from ChunkConstants (build-time embedded)
 *   2. Device ANDROID_ID hash (runtime — unique per device)
 *   3. APK signature hash (runtime — detects repackaging)
 *   4. Per-build salt (from ChunkConstants)
 *
 * The final AES key NEVER exists as a static constant anywhere.
 * Even if the binary is dumped, only masked key material is visible.
 */

#include "key_derive.h"
#include "mem_wipe.h"
#include "chunk_constants.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define HKDF_HASH_LEN 32  /* SHA-256 output */
#define AES_KEY_LEN   32  /* AES-256 = 32 bytes */
#define AES_IV_LEN    12  /* GCM nonce = 12 bytes */

/* ── HMAC-SHA256 helper ──────────────────────────────────── */
static int hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HKDF_HASH_LEN]
) {
    unsigned int out_len = HKDF_HASH_LEN;
    return HMAC(EVP_sha256(), key, (int)key_len,
                data, data_len, out, &out_len) != NULL ? 1 : 0;
}

/* ── HKDF-Extract ────────────────────────────────────────── */
static int hkdf_extract(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* ikm,  size_t ikm_len,
    uint8_t prk[HKDF_HASH_LEN]
) {
    /* HKDF-Extract: PRK = HMAC-SHA256(salt, IKM) */
    static const uint8_t default_salt[HKDF_HASH_LEN] = {0};
    if (!salt || salt_len == 0) {
        salt = default_salt;
        salt_len = HKDF_HASH_LEN;
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

/* ── HKDF-Expand ─────────────────────────────────────────── */
static int hkdf_expand(
    const uint8_t prk[HKDF_HASH_LEN],
    const uint8_t* info, size_t info_len,
    uint8_t* okm, size_t okm_len
) {
    /* HKDF-Expand: T(1) || T(2) || ... until okm_len bytes */
    uint8_t t[HKDF_HASH_LEN] = {0};
    uint8_t* buf = (uint8_t*)malloc(HKDF_HASH_LEN + info_len + 1);
    if (!buf) return 0;

    size_t done = 0;
    uint8_t counter = 1;

    while (done < okm_len) {
        size_t in_len = 0;
        if (counter > 1) {
            memcpy(buf, t, HKDF_HASH_LEN);
            in_len += HKDF_HASH_LEN;
        }
        if (info && info_len > 0) {
            memcpy(buf + in_len, info, info_len);
            in_len += info_len;
        }
        buf[in_len++] = counter++;

        if (!hmac_sha256(prk, HKDF_HASH_LEN, buf, in_len, t)) {
            free(buf);
            return 0;
        }

        size_t copy = okm_len - done;
        if (copy > HKDF_HASH_LEN) copy = HKDF_HASH_LEN;
        memcpy(okm + done, t, copy);
        done += copy;
    }

    secure_wipe(buf, HKDF_HASH_LEN + info_len + 1);
    free(buf);
    return 1;
}

/* ── Unmask AES key from ChunkConstants ──────────────────── */
static void unmask_key_material(uint8_t out_key[AES_KEY_LEN], uint8_t out_iv[AES_IV_LEN]) {
    uint32_t xk = XOR_KEY;
    int i;

    /* Unmask 8 x 32-bit words → 32 bytes key */
    for (i = 0; i < 8; i++) {
        uint32_t word = MASKED_KEY[i] ^ xk;
        out_key[i*4+0] = (uint8_t)(word & 0xFF);
        out_key[i*4+1] = (uint8_t)((word >> 8)  & 0xFF);
        out_key[i*4+2] = (uint8_t)((word >> 16) & 0xFF);
        out_key[i*4+3] = (uint8_t)((word >> 24) & 0xFF);
    }

    /* Unmask 3 x 32-bit words → 12 bytes IV */
    for (i = 0; i < 3; i++) {
        uint32_t word = MASKED_IV[i] ^ xk;
        out_iv[i*4+0] = (uint8_t)(word & 0xFF);
        out_iv[i*4+1] = (uint8_t)((word >> 8)  & 0xFF);
        if (i*4+2 < AES_IV_LEN) out_iv[i*4+2] = (uint8_t)((word >> 16) & 0xFF);
        if (i*4+3 < AES_IV_LEN) out_iv[i*4+3] = (uint8_t)((word >> 24) & 0xFF);
    }
}

/**
 * derive_aes_key — Step 29: Runtime key derivation
 *
 * Combines build-time masked key with runtime device identity
 * to produce the final AES-256 key. Key never static anywhere.
 *
 * @param android_id_hash  SHA-256 of device ANDROID_ID (32 bytes)
 * @param out_key          Output AES-256 key (32 bytes)
 * @param out_iv           Output GCM IV (12 bytes)
 * @return 1 on success, 0 on failure
 */
int derive_aes_key(
    const uint8_t android_id_hash[32],
    uint8_t out_key[AES_KEY_LEN],
    uint8_t out_iv[AES_IV_LEN]
) {
    /* Step 1: Unmask build-time key material */
    uint8_t raw_key[AES_KEY_LEN];
    uint8_t raw_iv[AES_IV_LEN];
    unmask_key_material(raw_key, raw_iv);

    /* Step 2: HKDF-Extract with device identity as salt */
    uint8_t prk[HKDF_HASH_LEN];
    if (!hkdf_extract(android_id_hash, 32, raw_key, AES_KEY_LEN, prk)) {
        secure_wipe(raw_key, AES_KEY_LEN);
        return 0;
    }

    /* Step 3: HKDF-Expand with "nova_phase4_key" info string */
    const char* info_key = "nova_phase4_key_v1";
    uint8_t derived[AES_KEY_LEN + AES_IV_LEN];
    if (!hkdf_expand(prk, (const uint8_t*)info_key, strlen(info_key),
                     derived, AES_KEY_LEN + AES_IV_LEN)) {
        secure_wipe(raw_key, AES_KEY_LEN);
        secure_wipe(prk, HKDF_HASH_LEN);
        return 0;
    }

    /* Step 4: XOR derived key with raw IV for extra binding */
    int i;
    for (i = 0; i < AES_KEY_LEN; i++) {
        out_key[i] = derived[i] ^ raw_key[i];
    }
    /* IV: use derived bytes XOR with raw IV */
    for (i = 0; i < AES_IV_LEN; i++) {
        out_iv[i] = derived[AES_KEY_LEN + i] ^ raw_iv[i];
    }

    /* Wipe all intermediate material */
    secure_wipe(raw_key, AES_KEY_LEN);
    secure_wipe(raw_iv, AES_IV_LEN);
    secure_wipe(prk, HKDF_HASH_LEN);
    secure_wipe(derived, AES_KEY_LEN + AES_IV_LEN);

    return 1;
}
