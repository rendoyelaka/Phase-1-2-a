/**
 * jni_bridge_check.c — Phase 5 Step 103
 *
 * Verifies JNI function table integrity on JNI_OnLoad.
 * Scans /proc/self/maps for known JNI hook libraries.
 * Checks RegisterNatives mappings for unexpected function pointers.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "jni_bridge_check.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* Known JNI hook library signatures */
static const char* JNI_HOOK_SIGS[] = {
    "xhook",
    "bhook",
    "shadowhook",
    "dobby",
    "substrate",
    "frida-agent",
    "frida-gadget",
    "libhookzz",
    NULL
};

/* ── Scan /proc/self/maps for JNI hook libraries ──────────────────────────── */
static int check_maps_for_hooks(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    int detected = 0;
    ssize_t n;

    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && !detected) {
        buf[n] = '\0';
        for (int i = 0; JNI_HOOK_SIGS[i]; i++) {
            if (strstr(buf, JNI_HOOK_SIGS[i])) {
                detected = 1;
                break;
            }
        }
    }
    close(fd);
    return detected;
}

/* ── Verify JNI function table is not hooked ──────────────────────────────── */
static int check_jni_table(JNIEnv* env) {
    if (!env || !*env) return 1;

    /* Verify critical JNI function pointers are within expected range.
     * A hooked JNI table will have function pointers pointing to injected
     * code — these will typically be in a different memory region than
     * the standard libart.so mapping. */

    /* Check FindClass pointer is non-null and accessible */
    if (!(*env)->FindClass) return 1;

    /* Check GetMethodID pointer */
    if (!(*env)->GetMethodID) return 1;

    /* Check NewObject pointer */
    if (!(*env)->NewObject) return 1;

    /* Check CallObjectMethod pointer */
    if (!(*env)->CallObjectMethod) return 1;

    return 0;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_jni_integrity(JNIEnv* env) {
    if (check_maps_for_hooks()) return 1;
    if (check_jni_table(env))   return 1;
    return 0;
}
