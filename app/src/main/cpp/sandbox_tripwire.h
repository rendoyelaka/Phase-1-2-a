/**
 * sandbox_tripwire.h — Phase 5 Step 122
 */
#ifndef SANDBOX_TRIPWIRE_H
#define SANDBOX_TRIPWIRE_H

#include <jni.h>

/**
 * check_sandbox_tripwire()
 * Weighted scoring: threshold >= 35 → sandbox detected.
 * Returns 1 if sandbox detected, 0 if clean.
 */
int check_sandbox_tripwire(JNIEnv* env, jobject context);

#endif /* SANDBOX_TRIPWIRE_H */
