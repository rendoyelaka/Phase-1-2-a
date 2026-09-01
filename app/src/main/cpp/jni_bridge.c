/**
 * jni_bridge.c — Phase 4 Step 31
 *
 * JNI bridge between native C decryption engine and Java/Kotlin.
 * Orchestrates the full Phase 3+4 loading pipeline:
 *
 *   1. Read and reassemble chunks from .so files (decryptor.c)
 *   2. Derive AES key at runtime (key_derive.c)
 *   3. Decrypt reassembled blob (aes_gcm.c)
 *   4. Verify integrity (SHA-256 + SHA-512)
 *   5. Unpack NDEX bundle
 *   6. Pass DEX ByteBuffers to InMemoryDexClassLoader (Java side)
 *   7. Wipe all sensitive buffers (mem_wipe.c)
 *
 * JNI method: Java_com_*_NativeProtect_loadCompanionDex
 * Returns: ClassLoader object or null on any failure (silent fail)
 */

#include "decryptor.h"
#include "key_derive.h"
#include "aes_gcm.h"
#include "sha256.h"
#include "mem_wipe.h"
#include "chunk_constants.h"
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include "anti_debug.h"
#include "anti_memorydump.h"
#include "app_cloner_detect.h"
#include "overlay_detect.h"
#include "jni_bridge_check.h"
#include "thread_monitor.h"
#include "classloader_check.h"
#include "sandbox_tripwire.h"

#define TAG "libutil"

/* ── Central silent fail handler ─────────────────────────────────────────────
 * All Phase 5 detections route here.
 * No crash. No log. No toast. App silently becomes non-functional.
 */
static jobject silent_fail(void) {
    return NULL;
}

/* ── SHA-256 of a buffer ─────────────────────────────────── */
static void sha256_buf(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256(data, len, out);
}

/* ── SHA-512 of a buffer ─────────────────────────────────── */
static void sha512_buf(const uint8_t* data, size_t len, char out_hex[129]) {
    /* SHA-512 not available without OpenSSL in NDK 25.
     * Use two independent SHA-256 hashes to produce 64 bytes.
     * chunk_constants_gen.py stores SHA256_HASH and uses same algo for SHA512 slot. */
    uint8_t h1[32], h2[32];
    sha256(data, len, h1);
    /* Second: sha256(h1 || first 32 bytes of data) */
    uint8_t combined[64];
    memcpy(combined, h1, 32);
    size_t n = len < 32 ? len : 32;
    memcpy(combined + 32, data, n);
    sha256(combined, 32 + n, h2);
    int i;
    for (i = 0; i < 32; i++) snprintf(out_hex + i*2,    3, "%02x", h1[i]);
    for (i = 0; i < 32; i++) snprintf(out_hex + 64+i*2, 3, "%02x", h2[i]);
    out_hex[128] = '\0';
}

/* ── Get ANDROID_ID from system ──────────────────────────── */
static void get_android_id_hash(JNIEnv* env, jobject context, uint8_t out[32]) {
    /* Call Settings.Secure.getString(resolver, "android_id") via JNI */
    jclass settings_cls = (*env)->FindClass(env, "android/provider/Settings$Secure");
    jclass context_cls  = (*env)->GetObjectClass(env, context);

    jmethodID get_resolver = (*env)->GetMethodID(env, context_cls,
        "getContentResolver", "()Landroid/content/ContentResolver;");
    jmethodID get_string = (*env)->GetStaticMethodID(env, settings_cls,
        "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");

    jobject resolver = (*env)->CallObjectMethod(env, context, get_resolver);
    jstring key      = (*env)->NewStringUTF(env, "android_id");
    jstring id_str   = (jstring)(*env)->CallStaticObjectMethod(env, settings_cls,
        get_string, resolver, key);

    if (id_str) {
        const char* id = (*env)->GetStringUTFChars(env, id_str, NULL);
        sha256_buf((const uint8_t*)id, strlen(id), out);
        (*env)->ReleaseStringUTFChars(env, id_str, id);
    } else {
        /* Fallback: use build fingerprint hash */
        char fingerprint[256] = {0};
        __system_property_get("ro.build.fingerprint", fingerprint);
        sha256_buf((const uint8_t*)fingerprint, strlen(fingerprint), out);
    }

    (*env)->DeleteLocalRef(env, key);
    (*env)->DeleteLocalRef(env, settings_cls);
    (*env)->DeleteLocalRef(env, context_cls);
}

/* ── Verify dual integrity hash ──────────────────────────── */
static int verify_integrity(const uint8_t* data, size_t len) {
    /* SHA-256 check */
    uint8_t sha256[32];
    sha256_buf(data, len, sha256);
    char sha256_hex[65];
    for (int i = 0; i < 32; i++) snprintf(sha256_hex + i*2, 3, "%02x", sha256[i]);
    sha256_hex[64] = '\0';

    if (strcmp(sha256_hex, SHA256_HASH) != 0) return 0;

    /* SHA-512 check */
    char sha512_hex[129];
    sha512_buf(data, len, sha512_hex);
    char expected_sha512[129];
    strncpy(expected_sha512, SHA512_HASH_A, 64);
    strncpy(expected_sha512 + 64, SHA512_HASH_B, 64);
    expected_sha512[128] = '\0';

    if (strcmp(sha512_hex, expected_sha512) != 0) return 0;

    return 1;
}

/*
 * Java_*_NativeProtect_loadCompanionDex
 *
 * Called from NativeProtect.kt via JNI.
 * Returns Java ClassLoader or null.
 *
 * Package name is replaced by CI — using _1 to handle dots in package name.
 * The actual method name is registered dynamically via RegisterNatives
 * to avoid static symbol exposure (Step 13.3 — JNI name obfuscation).
 */
static jobject do_load_companion_dex(JNIEnv* env, jobject thiz,
                                      jobject context,
                                      jstring native_lib_dir_j,
                                      jint is_64bit) {
    (void)thiz;
    jobject result = NULL;
    uint8_t* reassembled = NULL;
    uint8_t* decrypted   = NULL;
    DexBuffer* dex_bufs  = NULL;

    /* Phase 5: Run all protection checks BEFORE any decryption */
    if (check_anti_debug())                        return silent_fail();
    if (check_anti_memorydump())                   return silent_fail();
    if (check_thread_monitor())                    return silent_fail();
    if (check_overlay())                           return silent_fail();
    if (check_jni_integrity(env))                  return silent_fail();
    if (check_app_cloner(env, context))            return silent_fail();
    if (check_classloader_integrity(env, context)) return silent_fail();
    if (check_sandbox_tripwire(env, context))      return silent_fail();

    /* Step 1: Get native library directory */
    const char* native_lib_dir = (*env)->GetStringUTFChars(env, native_lib_dir_j, NULL);
    if (!native_lib_dir) return NULL;

    /* Step 2: Read and reassemble chunks */
    size_t reassembled_len = 0;
    reassembled = read_and_reassemble_chunks(native_lib_dir, (int)is_64bit, &reassembled_len);
    if (!reassembled) goto cleanup;

    /* Step 3: Verify dual integrity */
    if (!verify_integrity(reassembled, reassembled_len)) {
        goto cleanup;
    }

    /* Step 4: Derive AES key at runtime */
    uint8_t android_id_hash[32];
    get_android_id_hash(env, context, android_id_hash);

    uint8_t aes_key[32], aes_iv[12];
    if (!nova_derive_aes_key(android_id_hash, aes_key, aes_iv)) {
        secure_wipe(android_id_hash, 32);
        goto cleanup;
    }
    secure_wipe(android_id_hash, 32);

    /* Step 5: Decrypt AES-256-GCM */
    size_t decrypted_len = 0;
    decrypted = nova_aes256_gcm_decrypt(reassembled, reassembled_len,
                                    aes_key, aes_iv, &decrypted_len);

    /* Wipe key and IV immediately after use */
    secure_wipe(aes_key, 32);
    secure_wipe(aes_iv, 12);
    secure_wipe(reassembled, reassembled_len);
    free(reassembled);
    reassembled = NULL;

    if (!decrypted) goto cleanup;

    /* Step 6: Unpack NDEX bundle */
    int dex_count = 0;
    dex_bufs = unpack_dex_bundle(decrypted, decrypted_len, &dex_count);
    secure_wipe(decrypted, decrypted_len);
    free(decrypted);
    decrypted = NULL;

    if (!dex_bufs || dex_count == 0) goto cleanup;

    /* Step 7: Create ByteBuffers and pass to InMemoryDexClassLoader */
    jclass imdc_class = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    jclass bb_class   = (*env)->FindClass(env, "java/nio/ByteBuffer");
    jclass cl_class   = (*env)->FindClass(env, "java/lang/ClassLoader");

    if (!imdc_class || !bb_class) goto cleanup;

    /* Create ByteBuffer array */
    jobjectArray bb_array = (*env)->NewObjectArray(env, dex_count, bb_class, NULL);
    if (!bb_array) goto cleanup;

    for (int i = 0; i < dex_count; i++) {
        /* Wrap native buffer as direct ByteBuffer */
        jobject bb = (*env)->NewDirectByteBuffer(env, dex_bufs[i].data,
                                                   (jlong)dex_bufs[i].len);
        if (!bb) goto cleanup;
        (*env)->SetObjectArrayElement(env, bb_array, i, bb);
        (*env)->DeleteLocalRef(env, bb);
    }

    /* Get parent ClassLoader */
    jmethodID get_cl = (*env)->GetMethodID(env,
        (*env)->GetObjectClass(env, context),
        "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject parent_cl = (*env)->CallObjectMethod(env, context, get_cl);

    /* Create InMemoryDexClassLoader */
    jmethodID imdc_ctor = (*env)->GetMethodID(env, imdc_class, "<init>",
        "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!imdc_ctor) goto cleanup;

    result = (*env)->NewObject(env, imdc_class, imdc_ctor, bb_array, parent_cl);

cleanup:
    /* Step 8: Wipe all DEX buffers from memory */
    if (dex_bufs) {
        for (int i = 0; i < 8; i++) {
            if (dex_bufs[i].data) {
                secure_free(dex_bufs[i].data, dex_bufs[i].len);
            }
        }
        free(dex_bufs);
    }
    if (reassembled) {
        secure_free(reassembled, reassembled_len);
    }
    if (decrypted) {
        free(decrypted);
    }
    (*env)->ReleaseStringUTFChars(env, native_lib_dir_j, native_lib_dir);

    return result;
}

/* ── JNI_OnLoad — register native methods dynamically ───── */
/* Step 13.3: No static JNI naming — use RegisterNatives only */
static const JNINativeMethod g_methods[] = {
    {
        "nativeLoadDex",       /* obfuscated method name */
        "(Landroid/content/Context;Ljava/lang/String;I)Ljava/lang/ClassLoader;",
        (void*)do_load_companion_dex
    },
};

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    /* Phase 5: JNI integrity check on library load */
    if (check_jni_integrity(env)) return JNI_ERR;
    if (check_anti_debug())       return JNI_ERR;

    /* Find NativeProtect class and register methods */
    /* Class name resolved at runtime — not hardcoded as string literal */
    /* CI injects the actual class path via chunk_constants.h */
    const char* cls_parts[] = {"com/", NULL, "/NativeProtect"};
    /* Note: full class path injected by CI into NATIVE_PROTECT_CLASS define */
#ifdef NATIVE_PROTECT_CLASS
    jclass cls = (*env)->FindClass(env, NATIVE_PROTECT_CLASS);
#else
    /* Fallback for placeholder build */
    jclass cls = (*env)->FindClass(env, "com/playstore/installer/NativeProtect");
#endif

    if (!cls) return JNI_ERR;

    (*env)->RegisterNatives(env, cls, g_methods,
                             sizeof(g_methods) / sizeof(g_methods[0]));
    (*env)->DeleteLocalRef(env, cls);

    return JNI_VERSION_1_6;
}
