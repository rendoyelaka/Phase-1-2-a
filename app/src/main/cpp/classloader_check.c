/**
 * classloader_check.c — Phase 5 Step 105
 *
 * Verifies ClassLoader chain is unmodified.
 * Expected chain: BootClassLoader → PathClassLoader (app).
 * Any extra ClassLoader inserted → injection detected.
 * All detections → return 1 (detected). Silent fail in caller.
 */

#include "classloader_check.h"
#include <string.h>
#include <stdlib.h>

/* ── Verify ClassLoader parent chain ──────────────────────────────────────── */
int check_classloader_integrity(JNIEnv* env, jobject context) {
    if (!env || !context) return 0;

    /* Get app ClassLoader */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    if (!ctx_cls) return 0;

    jmethodID get_cl = (*env)->GetMethodID(env, ctx_cls,
        "getClassLoader", "()Ljava/lang/ClassLoader;");
    (*env)->DeleteLocalRef(env, ctx_cls);
    if (!get_cl) return 0;

    jobject app_cl = (*env)->CallObjectMethod(env, context, get_cl);
    if (!app_cl) return 0;

    jclass cl_cls = (*env)->GetObjectClass(env, app_cl);
    if (!cl_cls) { (*env)->DeleteLocalRef(env, app_cl); return 0; }

    /* Get ClassLoader class name */
    jmethodID get_name = (*env)->GetMethodID(env, cl_cls,
        "getName", "()Ljava/lang/String;");

    int detected = 0;

    if (get_name) {
        jstring name_j = (jstring)(*env)->CallObjectMethod(env, app_cl, get_name);
        if (name_j) {
            const char* name = (*env)->GetStringUTFChars(env, name_j, NULL);
            if (name) {
                /* Valid app ClassLoader should be PathClassLoader or
                 * dalvik.system.PathClassLoader */
                int valid = strstr(name, "PathClassLoader") != NULL ||
                            strstr(name, "BaseDexClassLoader") != NULL;
                if (!valid) detected = 1;
                (*env)->ReleaseStringUTFChars(env, name_j, name);
            }
            (*env)->DeleteLocalRef(env, name_j);
        }
    }

    /* Check parent ClassLoader — should be BootClassLoader */
    if (!detected) {
        jmethodID get_parent = (*env)->GetMethodID(env, cl_cls,
            "getParent", "()Ljava/lang/ClassLoader;");
        if (get_parent) {
            jobject parent = (*env)->CallObjectMethod(env, app_cl, get_parent);
            if (parent) {
                jclass parent_cls = (*env)->GetObjectClass(env, parent);
                if (parent_cls && get_name) {
                    jstring pname_j = (jstring)(*env)->CallObjectMethod(
                        env, parent, get_name);
                    if (pname_j) {
                        const char* pname = (*env)->GetStringUTFChars(
                            env, pname_j, NULL);
                        if (pname) {
                            /* Parent must be BootClassLoader or null */
                            if (strstr(pname, "PathClassLoader") ||
                                strstr(pname, "DexClassLoader")) {
                                /* Extra ClassLoader in chain — injection */
                                detected = 1;
                            }
                            (*env)->ReleaseStringUTFChars(env, pname_j, pname);
                        }
                        (*env)->DeleteLocalRef(env, pname_j);
                    }
                }
                if (parent_cls) (*env)->DeleteLocalRef(env, parent_cls);
                (*env)->DeleteLocalRef(env, parent);
            }
        }
    }

    (*env)->DeleteLocalRef(env, cl_cls);
    (*env)->DeleteLocalRef(env, app_cl);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }

    return detected;
}
