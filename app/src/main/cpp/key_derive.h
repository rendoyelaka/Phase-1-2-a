#ifndef KEY_DERIVE_H
#define KEY_DERIVE_H
#include <stdint.h>
#include <string.h>
int nova_derive_aes_key(
    const uint8_t android_id_hash[32],
    uint8_t out_key[32],
    uint8_t out_iv[12]
);
#endif
