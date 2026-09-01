/**
 * anti_memorydump.h — Phase 5 Step 100
 */
#ifndef ANTI_MEMORYDUMP_H
#define ANTI_MEMORYDUMP_H

#include <stdint.h>
#include <stddef.h>

/**
 * check_anti_memorydump()
 * Returns 1 if memory dump tool detected, 0 if clean.
 */
int check_anti_memorydump(void);

/**
 * poison_memory_region()
 * XOR-overwrites sensitive memory with 0xA5 pattern.
 * Uses volatile + memory barrier to prevent compiler optimization.
 */
void poison_memory_region(void* ptr, size_t len);

#endif /* ANTI_MEMORYDUMP_H */
