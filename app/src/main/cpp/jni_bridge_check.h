/**
 * jni_bridge_check.h — Phase 5 Step 103
 */
#ifndef JNI_BRIDGE_CHECK_H
#define JNI_BRIDGE_CHECK_H

#include <jni.h>

/**
 * check_jni_integrity()
 * Returns 1 if JNI hook detected, 0 if clean.
 */
int check_jni_integrity(JNIEnv* env);

#endif /* JNI_BRIDGE_CHECK_H */
