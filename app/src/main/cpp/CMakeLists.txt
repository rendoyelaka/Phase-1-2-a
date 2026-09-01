cmake_minimum_required(VERSION 3.22.1)
project("network_security_ext" C CXX)

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
    dead_code.c          # Step 35: fake functions to confuse disassemblers
    jni_bridge.c         # Step 31: JNI bridge to InMemoryDexClassLoader
    anti_debug.c         # Phase 5 Step 55: debugger detector
    anti_memorydump.c    # Phase 5 Step 100: memory dump protection
    app_cloner_detect.c  # Phase 5 Step 101: app cloner detection
    overlay_detect.c     # Phase 5 Step 102: overlay attack detection
    jni_bridge_check.c   # Phase 5 Step 103: JNI hook detection
    thread_monitor.c     # Phase 5 Step 104: thread monitoring
    classloader_check.c  # Phase 5 Step 105: ClassLoader integrity
    sandbox_tripwire.c   # Phase 5 Step 122: sandbox scoring
)

# Step 27: libnetwork_security_ext.so — dedicated protection library
add_library(network_security_ext SHARED ${PROTECT_SOURCES})

# Android NDK system libraries ONLY — no OpenSSL
find_library(log-lib     log)
find_library(android-lib android)

target_link_libraries(network_security_ext
    ${log-lib}
    ${android-lib}
)

target_include_directories(network_security_ext PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
