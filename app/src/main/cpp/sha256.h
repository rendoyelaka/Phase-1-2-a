#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>
void sha256(const uint8_t* data, size_t len, uint8_t digest[32]);
void hmac_sha256(const uint8_t* key, size_t klen,
                 const uint8_t* msg, size_t mlen, uint8_t digest[32]);
void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm,  size_t ikm_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* okm, size_t okm_len);
#endif
