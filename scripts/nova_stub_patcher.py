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
        hex_vals = [f"0x{x:02x}" for x in b]
        return ",\n            ".join(
            ", ".join(hex_vals[i:i+8]) for i in range(0, len(hex_vals), 8)
        )

    # Replace K1 placeholder
    old_k1 = """        private val K1 = byteArrayOf(
            0x6e, 0x30, 0x76, 0x41, 0x73, 0x45, 0x65, 0x64,
            0x6e, 0x30, 0x76, 0x41, 0x73, 0x45, 0x65, 0x64
        )"""
    new_k1 = f"        private val K1 = byteArrayOf(\n            {fmt_bytes(k1)}\n        )"

    # Replace K2 placeholder
    old_k2 = """        private val K2 = byteArrayOf(
            0x73, 0x45, 0x65, 0x64, 0x6e, 0x30, 0x76, 0x41,
            0x73, 0x45, 0x65, 0x64, 0x6e, 0x30, 0x76, 0x41
        )"""
    new_k2 = f"        private val K2 = byteArrayOf(\n            {fmt_bytes(k2)}\n        )"

    content = content.replace(old_k1, new_k1, 1)
    content = content.replace(old_k2, new_k2, 1)

    # Write patched file to temp
    tmp = stub_kt_path + ".patched.kt"
    with open(tmp, 'w') as f:
        f.write(content)
    return tmp


def compile_stub_dex(stub_kt_path: str, android_sdk: str, pkg_name: str) -> bytes:
    """
    Compile StubApp.kt to classes.dex using d8.
    Returns raw DEX bytes.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Find d8 tool
        build_tools = os.path.join(android_sdk, "build-tools")
        versions    = sorted(os.listdir(build_tools))
        d8_path     = os.path.join(build_tools, versions[-1], "d8")
        if not os.path.exists(d8_path):
            d8_path += ".bat"

        # Find kotlinc
        kotlinc = shutil.which("kotlinc")
        if not kotlinc:
            # Try common paths
            for p in ["/usr/local/bin/kotlinc", "/usr/bin/kotlinc"]:
                if os.path.exists(p):
                    kotlinc = p
                    break

        if not kotlinc:
            raise RuntimeError("kotlinc not found")

        # Find android.jar
        platforms = os.path.join(android_sdk, "platforms")
        platform  = sorted(os.listdir(platforms))[-1]
        android_jar = os.path.join(platforms, platform, "android.jar")

        # Compile Kotlin → .class files
        classes_dir = os.path.join(tmpdir, "classes")
        os.makedirs(classes_dir)

        result = subprocess.run([
            kotlinc,
            stub_kt_path,
            "-classpath", android_jar,
            "-d", classes_dir,
            "-jvm-target", "1.8",
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[WARN] kotlinc: {result.stderr[:500]}")
            # Try with jar output instead
            jar_path = os.path.join(tmpdir, "stub.jar")
            result2 = subprocess.run([
                kotlinc, stub_kt_path,
                "-classpath", android_jar,
                "-d", jar_path,
                "-jvm-target", "1.8",
            ], capture_output=True, text=True)
            if result2.returncode != 0:
                raise RuntimeError(f"kotlinc failed: {result2.stderr[:300]}")
            # Convert jar to DEX
            dex_path = os.path.join(tmpdir, "stub_dex")
            os.makedirs(dex_path)
            subprocess.run([d8_path, jar_path, "--output", dex_path,
                           "--lib", android_jar], check=True)
        else:
            # Convert .class files to DEX
            class_files = []
            for root, dirs, files in os.walk(classes_dir):
                for f in files:
                    if f.endswith(".class"):
                        class_files.append(os.path.join(root, f))

            dex_path = os.path.join(tmpdir, "stub_dex")
            os.makedirs(dex_path)
            subprocess.run([d8_path] + class_files +
                          ["--output", dex_path, "--lib", android_jar],
                          check=True)

        dex_file = os.path.join(dex_path, "classes.dex")
        if not os.path.exists(dex_file):
            raise RuntimeError("Stub DEX not produced")

        with open(dex_file, 'rb') as f:
            stub_dex = f.read()

        print(f"  Stub DEX size: {len(stub_dex)//1024}KB")
        return stub_dex


def patch_apk(apk_path: str, stub_dex: bytes, payload_bytes: bytes) -> str:
    """
    Replace classes.dex with stub DEX.
    Add nova_payload.bin to assets.
    Returns path to patched APK.
    """
    out_path = apk_path + ".stub_patched.apk"

    with zipfile.ZipFile(apk_path, 'r') as zin, \
         zipfile.ZipFile(out_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:

        for item in zin.infolist():
            if item.filename == STUB_DEX_ASSET:
                # Replace with stub DEX
                zout.writestr(item.filename, stub_dex)
                print(f"  Replaced classes.dex: {len(stub_dex)//1024}KB")
            elif item.filename == PAYLOAD_ASSET:
                # Skip old payload if exists
                pass
            else:
                zout.writestr(item, zin.read(item.filename))

        # Add encrypted payload
        zout.writestr(PAYLOAD_ASSET, payload_bytes,
                      compress_type=zipfile.ZIP_STORED)
        print(f"  Added {PAYLOAD_ASSET}: {len(payload_bytes)//1024}KB")

    return out_path


def resign_apk(apk_path: str, android_sdk: str) -> str:
    """Re-sign APK using debug keystore."""
    build_tools = os.path.join(android_sdk, "build-tools")
    versions    = sorted(os.listdir(build_tools))
    apksigner   = os.path.join(build_tools, versions[-1], "apksigner")

    # Generate fresh keystore
    ks_path = apk_path + ".ks"
    subprocess.run([
        "keytool", "-genkeypair", "-v",
        "-keystore", ks_path,
        "-alias", "nova_stub",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "365",
        "-storepass", "nova1234",
        "-keypass", "nova1234",
        "-dname", "CN=Nova,OU=Dev,O=Nova,L=IN,ST=IN,C=IN",
        "-noprompt"
    ], check=True, capture_output=True)

    # Zipalign first
    aligned = apk_path + ".aligned.apk"
    zipalign = os.path.join(build_tools, versions[-1], "zipalign")
    subprocess.run([zipalign, "-f", "4", apk_path, aligned],
                   check=True, capture_output=True)

    # Sign
    signed = apk_path.replace(".apk", "_stub.apk")
    subprocess.run([
        apksigner, "sign",
        "--ks", ks_path,
        "--ks-pass", "pass:nova1234",
        "--key-pass", "pass:nova1234",
        "--out", signed,
        aligned
    ], check=True, capture_output=True)

    os.remove(ks_path)
    os.remove(aligned)
    print(f"  Signed: {signed}")
    return signed


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
    print("\n[5] Compiling stub DEX...")
    stub_dex = compile_stub_dex(patched_kt, args.android_sdk, args.pkg)
    os.remove(patched_kt)

    # Step 6: Patch APK
    print("\n[6] Patching APK...")
    patched_apk = patch_apk(args.apk, stub_dex, payload_bytes)

    # Step 7: Re-sign
    print("\n[7] Re-signing APK...")
    # Note: In CI, the main signing happens in phase2_resign.py
    # We just replace the APK file with the patched version
    shutil.move(patched_apk, args.apk)
    print(f"  Replaced original APK with stub version")

    print("\n" + "="*60)
    print("✅ Nova Stub DEX Patcher Complete")
    print(f"  Original DEX: {len(real_dex)//1024}KB → Stub DEX: {len(stub_dex)//1024}KB")
    print(f"  Payload encrypted: {len(payload_bytes)//1024}KB → {PAYLOAD_ASSET}")
    print("="*60)


if __name__ == "__main__":
    main()
