#ifndef AES_GCM_H
#define AES_GCM_H
#include <stdint.h>
#include <stddef.h>
/* Decrypt blob produced by dex_encryptor.py.
   Format: [4-byte AAD len][AAD bytes][ciphertext+16-byte GCM tag]
   Returns malloc'd plaintext or NULL on failure. Caller must secure_free(). */
uint8_t* nova_aes256_gcm_decrypt(
    const uint8_t* encrypted, size_t enc_len,
    const uint8_t* key, const uint8_t* iv,
    size_t* out_len
);
#endif
