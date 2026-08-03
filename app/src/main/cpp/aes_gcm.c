/**
 * aes_gcm.c — Phase 4 Step 30
 * AES-256-GCM native decryption using Android NDK's BoringSSL.
 * All decryption happens in native C heap — never in Java heap.
 * Plaintext DEX held only in native memory.
 */

#include "aes_gcm.h"
#include "mem_wipe.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <android/log.h>

#define TAG    "libutil"
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16
#define AAD         "nova_companion_dex"
#define AAD_LEN     18

/**
 * aes256_gcm_decrypt — Step 30
 *
 * Decrypts data encrypted by dex_encryptor.py (AESGCM from cryptography lib).
 * Format from encryptor: [4-byte AAD len][AAD bytes][ciphertext+16-byte GCM tag]
 *
 * @param encrypted     Ciphertext (with AAD prefix)
 * @param enc_len       Length of encrypted buffer
 * @param key           AES-256 key (32 bytes)
 * @param iv            GCM nonce (12 bytes)
 * @param out_len       Output: length of decrypted plaintext
 * @return              Malloc'd plaintext buffer (caller must secure_free),
 *                      or NULL on failure.
 */
uint8_t* aes256_gcm_decrypt(
    const uint8_t* encrypted,
    size_t enc_len,
    const uint8_t* key,
    const uint8_t* iv,
    size_t* out_len
) {
    if (!encrypted || enc_len < 4 + AAD_LEN + GCM_TAG_LEN) return NULL;

    /* Parse AAD prefix: [4-byte AAD len][AAD bytes] */
    uint32_t aad_len = 0;
    memcpy(&aad_len, encrypted, 4);
    /* Android is always LE */

    if (aad_len > enc_len - 4) return NULL;
    const uint8_t* aad_ptr  = encrypted + 4;
    const uint8_t* cipher   = encrypted + 4 + aad_len;
    size_t cipher_len        = enc_len - 4 - aad_len;

    if (cipher_len < GCM_TAG_LEN) return NULL;

    size_t plaintext_len = cipher_len - GCM_TAG_LEN;
    const uint8_t* tag   = cipher + plaintext_len;

    uint8_t* plaintext = (uint8_t*)malloc(plaintext_len + 1);
    if (!plaintext) return NULL;

    /* Initialize AES-256-GCM context */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(plaintext); return NULL; }

    int ok = 1;
    int len = 0;

    /* Init decrypt */
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length */
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    /* Set key and IV */
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Set AAD */
    ok &= EVP_DecryptUpdate(ctx, NULL, &len, aad_ptr, (int)aad_len);
    /* Decrypt ciphertext */
    ok &= EVP_DecryptUpdate(ctx, plaintext, &len, cipher, (int)plaintext_len);
    int total = len;
    /* Set expected tag */
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag);
    /* Finalize — verifies GCM authentication tag */
    int final_ok = EVP_DecryptFinal_ex(ctx, plaintext + total, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok || final_ok <= 0) {
        /* Authentication failed — tampered data */
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return NULL;
    }

    total += len;
    plaintext[total] = 0;
    *out_len = (size_t)total;
    return plaintext;
}
