/**
 * decryptor.c — Phase 4 Step 28
 * Reads encrypted DEX chunks from .so files at XOR-unmasked offsets.
 * Reassembles chunks in correct sequence order.
 * All operations in native C heap memory.
 */

#include "decryptor.h"
#include "sha256.h"
#include "mem_wipe.h"
#include "crc_check.h"
#include "chunk_constants.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define TAG "libutil"

#define NCHK_MAGIC  0x4B43484E  /* "NCHK" as uint32_t LE */
#define NDEX_MAGIC  0x58454E44  /* "NDEX" as uint32_t LE */
#define HEADER_SIZE 44          /* magic(4)+idx(2)+total(2)+size(4)+sha256(32) */

/* ── Read bytes from file at offset ─────────────────────── */
static uint8_t* read_bytes_at(const char* path, uint64_t offset,
                               size_t size, size_t* out_read) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseeko(f, (off_t)offset, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) { fclose(f); return NULL; }

    size_t total = 0;
    while (total < size) {
        size_t r = fread(buf + total, 1, size - total, f);
        if (r == 0) break;
        total += r;
    }
    fclose(f);

    if (total != size) {
        free(buf);
        return NULL;
    }

    *out_read = total;
    return buf;
}

/* ── Parse chunk header ──────────────────────────────────── */
static int parse_chunk_header(const uint8_t* tagged, size_t tagged_len,
                               int expected_idx, int total_chunks,
                               const uint8_t** data_out, size_t* size_out) {
    if (tagged_len < HEADER_SIZE) return 0;

    /* Verify magic */
    uint32_t magic;
    memcpy(&magic, tagged, 4);
    if (magic != NCHK_MAGIC) return 0;

    uint16_t idx, n_chunks;
    uint32_t chunk_size;
    memcpy(&idx,        tagged + 4, 2);
    memcpy(&n_chunks,   tagged + 6, 2);
    memcpy(&chunk_size, tagged + 8, 4);

    if ((int)idx != expected_idx) return 0;
    if ((int)n_chunks != total_chunks) return 0;
    if (tagged_len < HEADER_SIZE + chunk_size) return 0;

    /* Verify SHA-256 integrity of chunk data */
    const uint8_t* stored_sha = tagged + 12;  /* 32 bytes */
    const uint8_t* data       = tagged + HEADER_SIZE;

    /* Compute SHA-256 via OpenSSL */
    uint8_t computed[32];
    sha256(data, chunk_size, computed);

    if (memcmp(computed, stored_sha, 32) != 0) {
        return 0; /* Integrity check failed */
    }

    *data_out = data;
    *size_out = chunk_size;
    return 1;
}

/**
 * read_and_reassemble_chunks — Step 28
 *
 * For each chunk index 0..N-1:
 *   1. XOR-unmask the offset and size
 *   2. Read chunk bytes from the corresponding .so file
 *   3. Validate NCHK header + SHA-256 integrity
 *   4. Store raw chunk data in order
 *
 * Then concatenates all chunks into the reassembled encrypted blob.
 *
 * @param native_lib_dir   Path to app's native library directory
 * @param is_64bit         1 for arm64-v8a, 0 for armeabi-v7a
 * @param out_len          Output: total reassembled length
 * @return                 Malloc'd buffer with reassembled encrypted blob,
 *                         or NULL on failure.
 */
uint8_t* read_and_reassemble_chunks(
    const char* native_lib_dir,
    int is_64bit,
    size_t* out_len
) {
    int n = N_CHUNKS;
    if (n <= 0 || n > 8) return NULL;

    /* Array to hold each chunk's data pointer and size */
    uint8_t** chunk_data  = (uint8_t**)calloc(n, sizeof(uint8_t*));
    size_t*   chunk_sizes = (size_t*)calloc(n, sizeof(size_t));
    if (!chunk_data || !chunk_sizes) {
        free(chunk_data);
        free(chunk_sizes);
        return NULL;
    }

    size_t total_size = 0;
    int success = 1;

    for (int i = 0; i < n && success; i++) {
        /* Get .so name for this chunk */
        const char* so_name = CHUNK_SO_NAMES[i];

        /* Build full path */
        char so_path[512];
        snprintf(so_path, sizeof(so_path), "%s/%s", native_lib_dir, so_name);

        /* Unmask offset and size */
        uint32_t masked_off = is_64bit ? CHUNK_MOFF_64[i] : CHUNK_MOFF_32[i];
        uint32_t masked_sz  = is_64bit ? CHUNK_MSZ_64[i]  : CHUNK_MSZ_32[i];
        uint64_t offset     = UNMASK_OFFSET(masked_off);
        uint32_t size       = UNMASK_SIZE(masked_sz);

        if (size == 0) { success = 0; break; }

        /* Read tagged chunk from .so */
        size_t bytes_read = 0;
        uint8_t* tagged = read_bytes_at(so_path, offset, size, &bytes_read);
        if (!tagged) { success = 0; break; }

        /* Parse header and validate */
        const uint8_t* data_ptr = NULL;
        size_t data_size = 0;
        if (!parse_chunk_header(tagged, bytes_read, i, n, &data_ptr, &data_size)) {
            secure_free(tagged, bytes_read);
            success = 0;
            break;
        }

        /* Copy chunk data (strip header) */
        chunk_data[i] = (uint8_t*)malloc(data_size);
        if (!chunk_data[i]) {
            secure_free(tagged, bytes_read);
            success = 0;
            break;
        }
        memcpy(chunk_data[i], data_ptr, data_size);
        chunk_sizes[i] = data_size;
        total_size += data_size;

        secure_free(tagged, bytes_read);
    }

    uint8_t* result = NULL;

    if (success && total_size > 0) {
        /* Reassemble in order */
        result = (uint8_t*)malloc(total_size);
        if (result) {
            size_t pos = 0;
            for (int i = 0; i < n; i++) {
                memcpy(result + pos, chunk_data[i], chunk_sizes[i]);
                pos += chunk_sizes[i];
            }
            *out_len = total_size;
        }
    }

    /* Wipe and free all chunk data */
    for (int i = 0; i < n; i++) {
        if (chunk_data[i]) {
            secure_free(chunk_data[i], chunk_sizes[i]);
        }
    }
    free(chunk_data);
    free(chunk_sizes);

    return result;
}

/**
 * unpack_dex_bundle — parse NDEX packed format
 * Format: NDEX(4) + count(4) + [len(4) + dex_bytes]...
 *
 * @param packed     Decrypted plaintext (NDEX format)
 * @param packed_len Length of packed buffer
 * @param out_count  Number of DEX files found
 * @return           Array of DexBuffer structs (caller frees each .data)
 */
DexBuffer* unpack_dex_bundle(const uint8_t* packed, size_t packed_len,
                              int* out_count) {
    if (packed_len < 8) return NULL;

    uint32_t magic, count;
    memcpy(&magic, packed, 4);
    memcpy(&count, packed + 4, 4);

    if (magic != NDEX_MAGIC) return NULL;
    if (count == 0 || count > 8) return NULL;

    DexBuffer* buffers = (DexBuffer*)calloc(count, sizeof(DexBuffer));
    if (!buffers) return NULL;

    size_t pos = 8;
    uint32_t i;
    for (i = 0; i < count; i++) {
        if (pos + 4 > packed_len) goto fail;
        uint32_t dex_len;
        memcpy(&dex_len, packed + pos, 4);
        pos += 4;

        if (pos + dex_len > packed_len) goto fail;
        buffers[i].data = (uint8_t*)malloc(dex_len);
        if (!buffers[i].data) goto fail;
        memcpy(buffers[i].data, packed + pos, dex_len);
        buffers[i].len = dex_len;
        pos += dex_len;
    }

    *out_count = (int)count;
    return buffers;

fail:
    for (i = 0; i < count; i++) {
        if (buffers[i].data) {
            secure_free(buffers[i].data, buffers[i].len);
        }
    }
    free(buffers);
    return NULL;
}
