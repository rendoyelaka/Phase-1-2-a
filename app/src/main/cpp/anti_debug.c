/**
 * anti_debug.c — Phase 5 Step 55
 *
 * Detects ADB debugging, JDWP debugger, and ptrace anti-debug.
 * All detections → silent_fail() → return 1 (detected).
 * NO crashes, NO logs, NO toasts ever.
 */

#include "anti_debug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <errno.h>

/* ── Check TracerPid in /proc/self/status ─────────────────────────────────── */
static int check_tracer_pid(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    p += 10;
    while (*p == ' ' || *p == '\t') p++;
    int tracer = atoi(p);
    return tracer != 0;
}

/* ── Check ptrace self-attach ─────────────────────────────────────────────── */
static int check_ptrace(void) {
    /* If we can ptrace ourselves we are not being traced.
     * If ptrace fails with EPERM → someone else already attached → debugger. */
    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret == -1 && errno == EPERM) return 1;
    /* Detach immediately if attach succeeded */
    if (ret == 0) ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
}

/* ── Check for JDWP socket ────────────────────────────────────────────────── */
static int check_jdwp(void) {
    /* JDWP creates a socket in /proc/net/unix */
    int fd = open("/proc/net/unix", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    int detected = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        if (strstr(buf, "jdwp")) { detected = 1; break; }
        if (strstr(buf, "jdwp-control")) { detected = 1; break; }
    }
    close(fd);
    return detected;
}

/* ── Check ADB connection via /proc/net/tcp ───────────────────────────────── */
static int check_adb_port(void) {
    /* ADB typically uses port 5555 (0x15B3) */
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) return 0;

    char buf[16384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Look for local address 0.0.0.0:5555 = 00000000:15B3 */
    return strstr(buf, ":15B3") != NULL || strstr(buf, ":15b3") != NULL;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_anti_debug(void) {
    if (check_tracer_pid()) return 1;
    if (check_ptrace())     return 1;
    if (check_jdwp())       return 1;
    if (check_adb_port())   return 1;
    return 0;
}
