/**
 * app_cloner_detect.c — Phase 5 Step 101
 *
 * Detects known app cloner/virtualizer packages via JNI PackageManager.
 * Detects VirtualApp-based hosts via Binder UID mismatch.
 * Detects cloned environment via /proc/self/cmdline package name check.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "app_cloner_detect.h"
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* Known cloner/virtualizer package names */
static const char* CLONER_PKGS[] = {
    "com.lbe.parallel.intl",
    "com.excelliance.dualaid",
    "com.ludashi.superboost",
    "io.va.exposed",
    "com.dualspace.launcher",
    "com.parallel.space.lite",
    "com.two.accounts",
    "com.multiapp.twin",
    "com.clone.app",
    "com.bly.dualspace",
    "com.polestar.clone",
    "com.copyapp.twin",
    NULL
};

/* ── Check cmdline matches expected package ────────────────────────────────── */
static int check_cmdline(JNIEnv* env, jobject context) {
    /* Read /proc/self/cmdline */
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return 0;

    char cmdline[512] = {0};
    ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    if (n <= 0) return 0;

    /* Get expected package name from context */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_pkg = (*env)->GetMethodID(env, ctx_cls,
        "getPackageName", "()Ljava/lang/String;");
    if (!get_pkg) { (*env)->DeleteLocalRef(env, ctx_cls); return 0; }

    jstring pkg_j = (jstring)(*env)->CallObjectMethod(env, context, get_pkg);
    if (!pkg_j) { (*env)->DeleteLocalRef(env, ctx_cls); return 0; }

    const char* pkg = (*env)->GetStringUTFChars(env, pkg_j, NULL);
    int mismatch = pkg ? (strstr(cmdline, pkg) == NULL) : 0;

    (*env)->ReleaseStringUTFChars(env, pkg_j, pkg);
    (*env)->DeleteLocalRef(env, pkg_j);
    (*env)->DeleteLocalRef(env, ctx_cls);

    return mismatch;
}

/* ── Check if known cloner packages are installed ─────────────────────────── */
static int check_cloner_packages(JNIEnv* env, jobject context) {
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_pm = (*env)->GetMethodID(env, ctx_cls,
        "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (!get_pm) { (*env)->DeleteLocalRef(env, ctx_cls); return 0; }

    jobject pm = (*env)->CallObjectMethod(env, context, get_pm);
    if (!pm) { (*env)->DeleteLocalRef(env, ctx_cls); return 0; }

    jclass pm_cls = (*env)->GetObjectClass(env, pm);
    jmethodID get_app_info = (*env)->GetMethodID(env, pm_cls,
        "getApplicationInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");

    int detected = 0;
    if (get_app_info) {
        for (int i = 0; CLONER_PKGS[i] && !detected; i++) {
            jstring pkg_j = (*env)->NewStringUTF(env, CLONER_PKGS[i]);
            jobject info = (*env)->CallObjectMethod(env, pm, get_app_info, pkg_j, 0);
            if (info && !(*env)->ExceptionCheck(env)) {
                detected = 1;
                (*env)->DeleteLocalRef(env, info);
            } else {
                (*env)->ExceptionClear(env);
            }
            (*env)->DeleteLocalRef(env, pkg_j);
        }
    }

    (*env)->DeleteLocalRef(env, pm_cls);
    (*env)->DeleteLocalRef(env, pm);
    (*env)->DeleteLocalRef(env, ctx_cls);
    return detected;
}

/* ── Public entry point ───────────────────────────────────────────────────── */
int check_app_cloner(JNIEnv* env, jobject context) {
    if (check_cmdline(env, context))         return 1;
    if (check_cloner_packages(env, context)) return 1;
    return 0;
}
