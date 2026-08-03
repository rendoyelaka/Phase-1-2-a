/* key_derive.c — Phase 4 Step 29: HKDF runtime key derivation. No OpenSSL. */
#include "key_derive.h"
#include "sha256.h"
#include "mem_wipe.h"
#include "chunk_constants.h"
#include <string.h>
#include <stdlib.h>

static void unmask(uint8_t key[32], uint8_t iv[12]) {
    uint32_t xk = XOR_KEY; int i;
    for(i=0;i<8;i++){uint32_t w=MASKED_KEY[i]^xk;
        key[i*4]=(uint8_t)(w&0xFF);key[i*4+1]=(uint8_t)((w>>8)&0xFF);
        key[i*4+2]=(uint8_t)((w>>16)&0xFF);key[i*4+3]=(uint8_t)((w>>24)&0xFF);}
    for(i=0;i<3;i++){uint32_t w=MASKED_IV[i]^xk;
        iv[i*4]=(uint8_t)(w&0xFF);iv[i*4+1]=(uint8_t)((w>>8)&0xFF);
        if(i*4+2<12)iv[i*4+2]=(uint8_t)((w>>16)&0xFF);
        if(i*4+3<12)iv[i*4+3]=(uint8_t)((w>>24)&0xFF);}
}

int nova_derive_aes_key(
    const uint8_t id_hash[32],
    uint8_t out_key[32], uint8_t out_iv[12]
) {
    uint8_t raw_key[32], raw_iv[12];
    unmask(raw_key, raw_iv);
    const char* info = "nova_phase4_key_v1";
    uint8_t derived[44];
    hkdf_sha256(id_hash, 32, raw_key, 32,
                (const uint8_t*)info, strlen(info), derived, 44);
    int i;
    for(i=0;i<32;i++) out_key[i]=derived[i]^raw_key[i];
    for(i=0;i<12;i++) out_iv[i]=derived[32+i]^raw_iv[i];
    secure_wipe(raw_key,32); secure_wipe(raw_iv,12); secure_wipe(derived,44);
    return 1;
}
