/**
 * thread_monitor.c — Phase 5 Step 104
 *
 * Monitors /proc/self/task for unexpected injected threads.
 * Checks known Frida/tool thread signatures in thread names.
 * Runs timing check to detect debugger slowing execution.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "thread_monitor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

/* Known Frida/tool thread name signatures */
static const char* FRIDA_THREAD_SIGS[] = {
    "gmain",
    "gdbus",
    "gum-js-loop",
    "frida",
    "pool-frida",
    "linjector",
    NULL
};

/* ── Read thread name from /proc/self/task/<tid>/comm ────────────────────── */
static int check_thread_names(void) {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return 0;

    struct dirent* entry;
    int detected = 0;

    while ((entry = readdir(dir)) != NULL && !detected) {
        if (entry->d_name[0] == '.') continue;

        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path),
                 "/proc/self/task/%s/comm", entry->d_name);

        int fd = open(comm_path, O_RDONLY);
        if (fd < 0) continue;

        char comm[64] = {0};
        ssize_t n = read(fd, comm, sizeof(comm) - 1);
        close(fd);
        if (n <= 0) continue;

        /* Strip newline */
        for (int i = 0; i < n; i++) {
            if (comm[i] == '\n') { comm[i] = '\0'; break; }
        }

        for (int i = 0; FRIDA_THREAD_SIGS[i]; i++) {
            if (strstr(comm, FRIDA_THREAD_SIGS[i])) {
                detected = 1;
                break;
            }
        }
    }
    closedir(dir);
    return detected;
}

/* ── Timing check — debugger slows clock_gettime ──────────────────────────── */
static int check_timing(void) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Simple busy loop — should complete in microseconds */
    volatile int x = 0;
    for (int i = 0; i < 10000; i++) x += i;
    (void)x;

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long elapsed_ms = (t2.tv_sec - t1.tv_sec) * 1000L +
                      (t2.tv_nsec - t1.tv_nsec) / 1000000L;

    /* If more than 500ms elapsed for a simple loop → debugger detected */
    return elapsed_ms > 500;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_thread_monitor(void) {
    if (check_thread_names()) return 1;
    if (check_timing())       return 1;
    return 0;
}
