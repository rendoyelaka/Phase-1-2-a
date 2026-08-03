/**
 * crc_check.c — Phase 4 Step 33
 * CRC-32 integrity checker for .so files.
 * Before decryption: verifies each .so not tampered post-install.
 * Mismatch → silent fail (no crash, no log, no toast).
 */

#include "crc_check.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#define TAG "libutil"

/* CRC-32 lookup table (IEEE polynomial 0xEDB88320) */
static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void init_crc32_table(void) {
    if (crc32_table_init) return;
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) {
            if (c & 1) c = 0xEDB88320 ^ (c >> 1);
            else c >>= 1;
        }
        crc32_table[i] = c;
    }
    crc32_table_init = 1;
}

uint32_t compute_crc32(const uint8_t* data, size_t len) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    size_t i;
    for (i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

/**
 * Verify a .so file's CRC against expected value.
 * Reads only the ELF portion (up to chunk_offset) to avoid
 * including the appended chunk data in the CRC.
 *
 * Returns 1 if OK, 0 if fail.
 */
int verify_so_crc(const char* so_path, uint64_t elf_size, uint32_t expected_crc) {
    FILE* f = fopen(so_path, "rb");
    if (!f) return 0;

    uint8_t* buf = (uint8_t*)malloc((size_t)elf_size);
    if (!buf) { fclose(f); return 0; }

    size_t read = fread(buf, 1, (size_t)elf_size, f);
    fclose(f);

    if (read != (size_t)elf_size) {
        free(buf);
        return 0;
    }

    uint32_t actual = compute_crc32(buf, (size_t)elf_size);
    free(buf);

    return (actual == expected_crc) ? 1 : 0;
}
