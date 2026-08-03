#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

uint8_t* aes256_gcm_decrypt(
    const uint8_t* encrypted, size_t enc_len,
    const uint8_t* key, const uint8_t* iv,
    size_t* out_len
);

#endif
