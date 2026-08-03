cmake_minimum_required(VERSION 3.22.1)
project("np_protect_res" C CXX)

# ── Compiler flags ────────────────────────────────────────────────────────────
# Step 26: Build for arm64-v8a and armeabi-v7a
# Step 35: Stack canary + ASLR-aware position-independent code

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fstack-protector-strong -fPIC -O2 -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIC -O2 -fvisibility=hidden -fno-rtti -fno-exceptions")

# Strip symbols in release builds (Step 34)
set(CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}   -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

# ── Source files ──────────────────────────────────────────────────────────────
set(PROTECT_SOURCES
    # Step 28: Chunk reader and reassembler
    decryptor.c

    # Step 29: Runtime AES key derivation (HKDF)
    key_derive.c

    # Step 30: AES-256-GCM native decryption (using BoringSSL/OpenSSL via Android NDK)
    aes_gcm.c

    # Step 32: Memory wiping after use
    mem_wipe.c

    # Step 33: CRC-32 integrity checker
    crc_check.c

    # Step 35: Dead code / fake functions (confuse disassemblers)
    dead_code.c

    # Step 31: JNI bridge — passes decrypted DEX to InMemoryDexClassLoader
    jni_bridge.c
)

# ── libnp_protect_res.so (Step 27 — dedicated protection library) ─────────────
add_library(
    np_protect_res
    SHARED
    ${PROTECT_SOURCES}
)

# Link Android NDK libraries
find_library(log-lib       log)
find_library(android-lib   android)

target_link_libraries(
    np_protect_res
    ${log-lib}
    ${android-lib}
)

# Link crypto (OpenSSL/BoringSSL from NDK for AES-256-GCM)
# Android NDK >= r21 provides libssl and libcrypto
target_link_libraries(np_protect_res ssl crypto)

# Include dirs
target_include_directories(np_protect_res PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ANDROID_NDK}/sysroot/usr/include
)

# Compile definitions — build UUID injected by CI (Step 24)
# These are written by chunk_constants_gen.py into a generated header
if(DEFINED BUILD_UUID)
    target_compile_definitions(np_protect_res PRIVATE
        BUILD_UUID="${BUILD_UUID}"
    )
endif()
