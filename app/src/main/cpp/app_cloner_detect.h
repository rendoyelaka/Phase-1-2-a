/**
 * app_cloner_detect.h — Phase 5 Step 101
 */
#ifndef APP_CLONER_DETECT_H
#define APP_CLONER_DETECT_H

#include <jni.h>

/**
 * check_app_cloner()
 * Returns 1 if app cloner/virtualizer detected, 0 if clean.
 */
int check_app_cloner(JNIEnv* env, jobject context);

#endif /* APP_CLONER_DETECT_H */
