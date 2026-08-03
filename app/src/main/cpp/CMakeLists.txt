cmake_minimum_required(VERSION 3.22.1)
project("np_protect_res" C CXX)

# Step 35: Stack canary + ASLR-aware position-independent code
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fstack-protector-strong -fPIC -O2 -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIC -O2 -fvisibility=hidden -fno-rtti -fno-exceptions")

# Step 34: Strip symbols in release
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--strip-all")

# ALL self-contained sources — NO external dependencies, NO OpenSSL
set(PROTECT_SOURCES
    sha256.c        # Self-contained SHA-256 + HMAC-SHA256 + HKDF (RFC 4634/2104/5869)
    aes256.c        # Self-contained AES-256-GCM (FIPS 197 + NIST SP 800-38D)
    aes_gcm.c       # AES-GCM wrapper using aes256.c
    key_derive.c    # Step 29: HKDF runtime key derivation
    mem_wipe.c      # Step 32: secure memory wipe
    crc_check.c     # Step 33: CRC-32 integrity checker
    decryptor.c     # Step 28: chunk reader and reassembler
    dead_code.c     # Step 35: fake functions to confuse disassemblers
    jni_bridge.c    # Step 31: JNI bridge to InMemoryDexClassLoader
)

# Step 27: libnp_protect_res.so — dedicated protection library
add_library(np_protect_res SHARED ${PROTECT_SOURCES})

# Android NDK system libraries ONLY — no OpenSSL
find_library(log-lib     log)
find_library(android-lib android)

target_link_libraries(np_protect_res
    ${log-lib}
    ${android-lib}
)

target_include_directories(np_protect_res PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
