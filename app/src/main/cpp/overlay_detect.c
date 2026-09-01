/**
 * overlay_detect.c — Phase 5 Step 102
 *
 * Detects overlay/tapjacking attack tools.
 * Native layer scans /proc/self/maps for known overlay tool libraries.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "overlay_detect.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* Known overlay tool library signatures */
static const char* OVERLAY_SIGS[] = {
    "mediaproject",
    "overlayservice",
    "accessibilityservice",
    "overlayattack",
    "tapjack",
    "screenoverlay",
    NULL
};

/* ── Check /proc/self/maps for overlay tool libraries ─────────────────────── */
static int check_maps_for_overlay(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    int detected = 0;
    ssize_t n;

    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && !detected) {
        buf[n] = '\0';
        for (int i = 0; OVERLAY_SIGS[i]; i++) {
            if (strstr(buf, OVERLAY_SIGS[i])) {
                detected = 1;
                break;
            }
        }
    }
    close(fd);
    return detected;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_overlay(void) {
    if (check_maps_for_overlay()) return 1;
    return 0;
}
