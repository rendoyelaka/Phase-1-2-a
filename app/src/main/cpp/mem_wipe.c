/**
 * mem_wipe.c — Phase 4 Step 32
 * Secure memory wiping implementation.
 */

#include "mem_wipe.h"
#include <string.h>
#include <stdlib.h>

void secure_wipe(void* buf, size_t len) {
    if (!buf || len == 0) return;

    /* volatile pointer prevents compiler from optimizing away */
    volatile uint8_t* p = (volatile uint8_t*)buf;
    size_t i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }

    /* Memory barrier — ensures the write is not reordered */
    __asm__ __volatile__("" ::: "memory");
}

void secure_free(void* buf, size_t len) {
    if (!buf) return;
    secure_wipe(buf, len);
    free(buf);
}
