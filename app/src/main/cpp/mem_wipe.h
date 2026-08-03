/**
 * mem_wipe.h — Phase 4 Step 32
 * Secure memory wiping — prevents compiler from optimizing away sensitive clears.
 * Uses volatile pointer trick + memory barrier.
 */

#ifndef MEM_WIPE_H
#define MEM_WIPE_H

#include <stddef.h>
#include <stdint.h>

/**
 * Securely zero-fill a buffer.
 * Compiler cannot optimize this away (volatile + memory barrier).
 */
void secure_wipe(void* buf, size_t len);

/**
 * Wipe and free a malloc'd buffer.
 */
void secure_free(void* buf, size_t len);

#endif /* MEM_WIPE_H */
