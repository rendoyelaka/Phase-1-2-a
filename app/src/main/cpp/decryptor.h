#ifndef DECRYPTOR_H
#define DECRYPTOR_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t* data;
    size_t   len;
} DexBuffer;

uint8_t* read_and_reassemble_chunks(
    const char* native_lib_dir,
    int is_64bit,
    size_t* out_len
);

DexBuffer* unpack_dex_bundle(
    const uint8_t* packed, size_t packed_len,
    int* out_count
);

#endif
