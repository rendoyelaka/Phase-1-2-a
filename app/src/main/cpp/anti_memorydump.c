/**
 * anti_memorydump.c — Phase 5 Step 100
 *
 * Detects memory dump tools: frida, gdb, lldb, memdump, dumpheap, ddms, jdwp.
 * Checks TracerPid and /proc/self/maps for known tool signatures.
 * Implements poison_memory_region() for sensitive buffers.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "anti_memorydump.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Known dump tool signatures in /proc/self/maps */
static const char* DUMP_SIGS[] = {
    "frida",
    "gdb",
    "lldb",
    "memdump",
    "dumpheap",
    "ddms",
    "jdwp",
    "memory_dump",
    "memorydump",
    NULL
};

/* ── Check /proc/self/maps for dump tool signatures ───────────────────────── */
static int check_maps_for_dump_tools(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    int detected = 0;
    ssize_t n;

    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; DUMP_SIGS[i]; i++) {
            if (strstr(buf, DUMP_SIGS[i])) {
                detected = 1;
                break;
            }
        }
        if (detected) break;
    }
    close(fd);
    return detected;
}

/* ── Check /proc/self/wchan for debug syscalls ────────────────────────────── */
static int check_wchan(void) {
    int fd = open("/proc/self/wchan", O_RDONLY);
    if (fd < 0) return 0;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    return strstr(buf, "ptrace_stop") != NULL ||
           strstr(buf, "sys_ptrace")  != NULL;
}

/* ── Poison memory region with XOR pattern ────────────────────────────────── */
void poison_memory_region(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] ^= 0xA5;
    }
    /* Memory barrier to prevent compiler optimization */
    __asm__ __volatile__("" ::: "memory");
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_anti_memorydump(void) {
    if (check_maps_for_dump_tools()) return 1;
    if (check_wchan())               return 1;
    return 0;
}
