/**
 * classloader_check.h — Phase 5 Step 105
 */
#ifndef CLASSLOADER_CHECK_H
#define CLASSLOADER_CHECK_H

#include <jni.h>

/**
 * check_classloader_integrity()
 * Returns 1 if ClassLoader chain tampered, 0 if clean.
 */
int check_classloader_integrity(JNIEnv* env, jobject context);

#endif /* CLASSLOADER_CHECK_H */
