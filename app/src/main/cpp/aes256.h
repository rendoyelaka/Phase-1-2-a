#ifndef AES256_H
#define AES256_H
#include <stdint.h>
#include <stddef.h>
int aes256_gcm_encrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* plain, size_t plain_len,
                       uint8_t* cipher, uint8_t tag[16]);
int aes256_gcm_decrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* cipher, size_t cipher_len,
                       const uint8_t tag[16], uint8_t* plain);
#endif
