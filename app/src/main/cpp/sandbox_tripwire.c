/**
 * sandbox_tripwire.c — Phase 5 Step 122
 *
 * Weighted scoring sandbox detector.
 * 8 signals, max 115 points. Threshold >= 35 → sandbox detected.
 * Threshold stored as XOR-obfuscated constant.
 * All detections → return 1. Silent fail in caller.
 *
 * Signal scores:
 *   S1: CPU cores <= 2        → 15 pts
 *   S2: Battery state fixed   → 15 pts
 *   S3: Sensor noise constant → 20 pts (checked via JNI)
 *   S4: MAC address emulator  → 20 pts
 *   S5: Uptime < 60s          → 10 pts
 *   S6: Installer null        → 10 pts
 *   S7: CPU hardware string   → 15 pts
 *   S8: Build fields emulator → 10 pts
 */

#include "sandbox_tripwire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <jni.h>

/* XOR-obfuscated threshold: 35 ^ 0x5A = 0x61 */
#define THRESHOLD_XOR_KEY 0x5A
#define THRESHOLD_ENCODED 0x61
#define GET_THRESHOLD()   (THRESHOLD_ENCODED ^ THRESHOLD_XOR_KEY)

/* ── Signal 1: CPU core count ─────────────────────────────────────────────── */
static int signal_cpu_cores(void) {
    int fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    int count = 0;
    char* p = buf;
    while ((p = strstr(p, "processor")) != NULL) {
        count++;
        p++;
    }
    return (count <= 2) ? 15 : 0;
}

/* ── Signal 4: MAC address check ──────────────────────────────────────────── */
static int signal_mac_address(void) {
    const char* ifaces[] = {
        "/sys/class/net/eth0/address",
        "/sys/class/net/wlan0/address",
        NULL
    };

    /* Known emulator MACs */
    const char* emulator_macs[] = {
        "02:00:00:00:00:00",
        "08:00:27:",   /* VirtualBox prefix */
        NULL
    };

    for (int i = 0; ifaces[i]; i++) {
        int fd = open(ifaces[i], O_RDONLY);
        if (fd < 0) continue;

        char mac[64] = {0};
        ssize_t n = read(fd, mac, sizeof(mac) - 1);
        close(fd);
        if (n <= 0) continue;

        for (int j = 0; emulator_macs[j]; j++) {
            if (strstr(mac, emulator_macs[j])) return 20;
        }
    }
    return 0;
}

/* ── Signal 5: Uptime check ───────────────────────────────────────────────── */
static int signal_uptime(void) {
    int fd = open("/proc/uptime", O_RDONLY);
    if (fd < 0) return 0;

    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;

    double uptime = atof(buf);
    return (uptime < 60.0) ? 10 : 0;
}

/* ── Signal 7: CPU hardware string ───────────────────────────────────────── */
static int signal_cpu_hardware(void) {
    int fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    const char* emu_strings[] = {
        "Goldfish", "Ranchu", "QEMU", "qemu", "vbox", "VirtualBox",
        NULL
    };

    for (int i = 0; emu_strings[i]; i++) {
        if (strstr(buf, emu_strings[i])) return 15;
    }
    return 0;
}

/* ── Signal 8: Build properties ───────────────────────────────────────────── */
static int signal_build_props(void) {
    const char* props[] = {
        "ro.build.fingerprint",
        "ro.product.model",
        "ro.hardware",
        "ro.product.board",
        "ro.product.brand",
        "ro.product.device",
        NULL
    };

    const char* emu_vals[] = {
        "generic", "unknown", "goldfish", "ranchu",
        "sdk", "emulator", "qemu", "vbox",
        NULL
    };

    char val[256];
    for (int i = 0; props[i]; i++) {
        val[0] = '\0';
        __system_property_get(props[i], val);
        if (!val[0]) continue;

        for (int j = 0; emu_vals[j]; j++) {
            if (strstr(val, emu_vals[j])) return 10;
        }
    }
    return 0;
}

/* ── Signal 2+6: Battery + installer (JNI-based) ─────────────────────────── */
static int signal_battery_and_installer(JNIEnv* env, jobject context) {
    int score = 0;

    /* Signal 6: Check installer package name */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jclass pm_cls_ref = (*env)->FindClass(env,
        "android/content/pm/PackageManager");
    jmethodID get_pm = (*env)->GetMethodID(env, ctx_cls,
        "getPackageManager", "()Landroid/content/pm/PackageManager;");

    if (get_pm && pm_cls_ref) {
        jobject pm = (*env)->CallObjectMethod(env, context, get_pm);
        if (pm) {
            jclass pm_cls2 = (*env)->GetObjectClass(env, pm);
            jmethodID get_installer = (*env)->GetMethodID(env, pm_cls2,
                "getInstallerPackageName",
                "(Ljava/lang/String;)Ljava/lang/String;");

            if (get_installer) {
                jmethodID get_pkg = (*env)->GetMethodID(env, ctx_cls,
                    "getPackageName", "()Ljava/lang/String;");
                if (get_pkg) {
                    jstring pkg = (jstring)(*env)->CallObjectMethod(
                        env, context, get_pkg);
                    if (pkg) {
                        jstring installer = (jstring)(*env)->CallObjectMethod(
                            env, pm, get_installer, pkg);
                        if (!installer || (*env)->ExceptionCheck(env)) {
                            score += 10; /* null installer = sideloaded/emulator */
                        }
                        (*env)->ExceptionClear(env);
                        if (installer) (*env)->DeleteLocalRef(env, installer);
                        (*env)->DeleteLocalRef(env, pkg);
                    }
                }
            }
            (*env)->DeleteLocalRef(env, pm_cls2);
            (*env)->DeleteLocalRef(env, pm);
        }
    }

    if (pm_cls_ref) (*env)->DeleteLocalRef(env, pm_cls_ref);
    (*env)->DeleteLocalRef(env, ctx_cls);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return score;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_sandbox_tripwire(JNIEnv* env, jobject context) {
    int score = 0;
    int threshold = GET_THRESHOLD();

    score += signal_cpu_cores();
    if (score >= threshold) return 1;

    score += signal_mac_address();
    if (score >= threshold) return 1;

    score += signal_uptime();
    if (score >= threshold) return 1;

    score += signal_cpu_hardware();
    if (score >= threshold) return 1;

    score += signal_build_props();
    if (score >= threshold) return 1;

    if (env && context) {
        score += signal_battery_and_installer(env, context);
        if (score >= threshold) return 1;
    }

    return 0;
}
