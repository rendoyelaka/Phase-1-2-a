/**
 * dead_code.c — Phase 4 Step 35
 * Fake unreachable C functions injected to confuse disassemblers (Ghidra, IDA).
 * These functions are never called — linker may optimize them away
 * but with -O0 or when referenced via function pointer they survive.
 * Different fake function names per build (CI can regenerate this file).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Fake analytics functions — looks like legitimate analytics SDK code */
__attribute__((used)) static int analytics_flush_queue(void* queue, int timeout_ms) {
    (void)queue; (void)timeout_ms;
    return -1;
}

__attribute__((used)) static void* analytics_create_session(const char* app_id, int flags) {
    (void)app_id; (void)flags;
    return NULL;
}

__attribute__((used)) static int network_send_beacon(const uint8_t* data, size_t len,
                                                       const char* endpoint) {
    (void)data; (void)len; (void)endpoint;
    return 0;
}

/* Fake crash reporter */
__attribute__((used)) static void crash_report_init(const char* dsn, int capture_native) {
    (void)dsn; (void)capture_native;
}

__attribute__((used)) static int crash_report_capture(void* ctx, const char* msg) {
    (void)ctx; (void)msg;
    return 0;
}

/* Fake config reader */
__attribute__((used)) static const char* config_get_string(const char* key,
                                                             const char* default_val) {
    (void)key;
    return default_val;
}

__attribute__((used)) static int config_get_int(const char* key, int default_val) {
    (void)key;
    return default_val;
}

/* Fake device info */
__attribute__((used)) static void device_info_collect(void* ctx) {
    (void)ctx;
}

__attribute__((used)) static int device_info_get_battery_level(void) {
    return 100;
}

/* Function pointer table — forces linker to keep these symbols */
typedef void (*fn_ptr_t)(void);
__attribute__((used)) static fn_ptr_t __dead_fn_table[] = {
    (fn_ptr_t)analytics_flush_queue,
    (fn_ptr_t)analytics_create_session,
    (fn_ptr_t)network_send_beacon,
    (fn_ptr_t)crash_report_init,
    (fn_ptr_t)crash_report_capture,
    (fn_ptr_t)config_get_string,
    (fn_ptr_t)config_get_int,
    (fn_ptr_t)device_info_collect,
    (fn_ptr_t)device_info_get_battery_level,
};
