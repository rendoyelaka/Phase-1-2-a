/* aes_gcm.c — AES-256-GCM wrapper using self-contained aes256.c. No OpenSSL. */
#include "aes_gcm.h"
#include "aes256.h"
#include "mem_wipe.h"
#include <stdlib.h>
#include <string.h>

uint8_t* nova_aes256_gcm_decrypt(
    const uint8_t* enc, size_t enc_len,
    const uint8_t* key, const uint8_t* iv,
    size_t* out_len
) {
    if (!enc || enc_len < 4 + 16) return NULL;
    uint32_t aad_len = 0;
    memcpy(&aad_len, enc, 4);
    if ((size_t)aad_len + 4 + 16 > enc_len) return NULL;
    const uint8_t* aad    = enc + 4;
    const uint8_t* cipher = enc + 4 + aad_len;
    size_t cl = enc_len - 4 - aad_len;
    if (cl < 16) return NULL;
    size_t pl = cl - 16;
    const uint8_t* tag = cipher + pl;
    uint8_t* plain = (uint8_t*)malloc(pl + 1);
    if (!plain) return NULL;
    int ok = aes256_gcm_decrypt(key, iv, aad, aad_len, cipher, pl, tag, plain);
    if (!ok) { secure_wipe(plain, pl); free(plain); return NULL; }
    plain[pl] = 0;
    *out_len = pl;
    return plain;
}
