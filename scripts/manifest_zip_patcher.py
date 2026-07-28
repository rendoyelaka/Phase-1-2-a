#!/usr/bin/env python3
"""
manifest_zip_patcher.py — Steps 17D / 17E / 17F

Step 17D — Binary manifest AES-256-GCM string encryption
    Selected non-critical string values inside the binary AndroidManifest.xml
    (AXML format) are encrypted with AES-256-GCM using a per-build key.
    The encrypted blobs replace the original string bytes in the AXML string pool.
    The native layer decrypts them before manifest parsing at runtime.
    NOTE: Only decoy/non-essential strings are encrypted — package name,
    activity names and permissions are left intact so Android can install/run.

Step 17E — Fake encrypted blocks injection in manifest
    Non-functional binary blocks that look like AES-GCM ciphertext
    (random nonce + random bytes) are injected into the AXML string pool
    after the real strings. Confuses RE tools and automated manifest parsers.

Step 17F — Random manifest binary padding
    Random-length binary padding is appended to the AXML file data inside
    the APK. Each build produces a different manifest binary size.
    Defeats manifest-based APK fingerprinting.

Usage:
    python3 scripts/manifest_zip_patcher.py <apk_in> <apk_out> <aes_key_hex>

    aes_key_hex : 64-char hex string (32 bytes = AES-256 key) from fingerprint generator.

Re-sign after running:
    zipalign -f 4 apk_out apk_aligned.apk
    apksigner sign --ks ... apk_aligned.apk
"""

import sys
import os
import struct
import secrets
import zipfile
import random

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# ── AXML constants ─────────────────────────────────────────────────────────────
AXML_MAGIC        = b'\x03\x00\x08\x00'   # AXML file header type + headerSize
STRING_POOL_TYPE  = 0x0001
UTF8_FLAG         = 1 << 8

# Strings we MUST NOT encrypt (Android needs them to parse the manifest)
PROTECTED_STRINGS = {
    'android', 'package', 'android.permission',
    'activity', 'service', 'receiver', 'provider',
    'uses-permission', 'application', 'manifest',
    'http://schemas.android.com/apk/res/android',
}

# Fake encrypted block marker (Step 17E)
FAKE_BLOCK_MARKER = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'

# Padding bounds for Step 17F (bytes)
PAD_MIN = 64
PAD_MAX = 512


# ── AES-256-GCM encrypt / decrypt ─────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Returns nonce(12) + ciphertext + tag(16)."""
    if HAS_PYCRYPTODOME:
        nonce  = secrets.token_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ct + tag
    else:
        # Fallback: XOR with key-derived stream (no PyCryptodome)
        # Still confuses parsers; not real GCM but structurally similar.
        nonce  = secrets.token_bytes(12)
        stream = bytearray()
        for i in range(0, len(plaintext) + 16, 32):
            stream.extend((k ^ (i & 0xFF)) for k in key)
        ct  = bytes(p ^ s for p, s in zip(plaintext, stream))
        tag = secrets.token_bytes(16)
        return nonce + ct + tag


def fake_gcm_block(min_len=16, max_len=128) -> bytes:
    """Step 17E — generate a random blob that looks like AES-GCM ciphertext."""
    length = random.randint(min_len, max_len)
    return FAKE_BLOCK_MARKER + secrets.token_bytes(12) + secrets.token_bytes(length) + secrets.token_bytes(16)


# ── AXML string pool parser / patcher ─────────────────────────────────────────

def patch_axml(axml_data: bytes, aes_key: bytes, skip_17d: bool = False) -> bytes:
    """
    Patches the AXML binary string pool:
      - Step 17D: encrypts selected non-critical string values
                  (skipped when skip_17d=True — requires Phase 4 native decryptor)
      - Step 17E: injects fake encrypted blocks (always applied)
      - Step 17F: appends random padding (always applied)
    Returns modified AXML bytes.
    """
    if len(axml_data) < 8:
        return axml_data

    data = bytearray(axml_data)

    # ── Locate string pool chunk ──────────────────────────────────────────────
    # AXML layout: [file header 8 bytes][string pool chunk][xml tree chunks...]
    SP = 8
    if len(data) < SP + 28:
        return bytes(data)

    sp_type       = struct.unpack_from('<H', data, SP)[0]
    sp_hdr_size   = struct.unpack_from('<H', data, SP + 2)[0]
    sp_chunk_size = struct.unpack_from('<I', data, SP + 4)[0]
    str_count     = struct.unpack_from('<I', data, SP + 8)[0]
    style_count   = struct.unpack_from('<I', data, SP + 12)[0]
    flags         = struct.unpack_from('<I', data, SP + 16)[0]
    strings_start = struct.unpack_from('<I', data, SP + 20)[0]
    styles_start  = struct.unpack_from('<I', data, SP + 24)[0]

    if sp_type != STRING_POOL_TYPE or str_count == 0:
        return bytes(data)

    is_utf8 = bool(flags & UTF8_FLAG)

    str_data_base = SP + strings_start
    offsets_base  = SP + sp_hdr_size

    # Read string offsets
    offsets = [
        struct.unpack_from('<I', data, offsets_base + i * 4)[0]
        for i in range(str_count)
    ]

    # Read strings (UTF-8 pool only — UTF-16 left untouched)
    strings = []
    if is_utf8:
        for off in offsets:
            pos = str_data_base + off
            if pos >= len(data):
                strings.append(None)
                continue
            b0 = data[pos]; pos += 1
            char_len = ((b0 & 0x7F) << 8) | data[pos] if b0 & 0x80 else b0
            if b0 & 0x80: pos += 1
            b1 = data[pos]; pos += 1
            byte_len = ((b1 & 0x7F) << 8) | data[pos] if b1 & 0x80 else b1
            if b1 & 0x80: pos += 1
            s = data[pos:pos+byte_len].decode('utf-8', errors='replace')
            strings.append(s)
    else:
        strings = [None] * str_count   # UTF-16: skip Step 17D encryption

    # ── Step 17D — encrypt selected strings ──────────────────────────────────
    # We build a new string pool where eligible strings are replaced by
    # their AES-GCM encrypted form encoded as a hex string.
    # The native decryption layer looks for strings starting with "ENC:" prefix.
    encrypted_count = 0

    def encode_utf8_str(s: str) -> bytes:
        enc = s.encode('utf-8')
        cl, bl = len(s), len(enc)
        hdr  = (bytes([(cl >> 8) | 0x80, cl & 0xFF]) if cl > 0x7F else bytes([cl]))
        hdr += (bytes([(bl >> 8) | 0x80, bl & 0xFF]) if bl > 0x7F else bytes([bl]))
        return hdr + enc + b'\x00'

    new_str_data = bytearray()
    new_offsets  = []

    for i, s in enumerate(strings):
        new_offsets.append(len(new_str_data))
        if s is None:
            # Non-UTF8 or out-of-bounds — copy original bytes
            pos = str_data_base + offsets[i]
            # Read until null terminator (best-effort)
            end = pos
            while end < len(data) and data[end] != 0:
                end += 1
            new_str_data.extend(data[pos:end+1])
            continue

        # Decide if this string is eligible for encryption
        # skip_17d=True for companion APK — Phase 4 native decryptor not yet
        # implemented. Encrypting strings now breaks Android manifest parsing.
        should_encrypt = (
            not skip_17d
            and is_utf8
            and len(s) >= 4
            and not any(s.startswith(p) for p in PROTECTED_STRINGS)
            and not s.startswith('ENC:')
            and random.random() < 0.3   # encrypt ~30% of eligible strings
        )
        if should_encrypt and aes_key:
            ct_bytes  = aes_gcm_encrypt(aes_key, s.encode('utf-8'))
            enc_str   = 'ENC:' + ct_bytes.hex()
            new_str_data.extend(encode_utf8_str(enc_str))
            encrypted_count += 1
        else:
            new_str_data.extend(encode_utf8_str(s))

    if skip_17d:
        print(f"[manifest_zip_patcher] Step 17D — SKIPPED (companion mode, needs Phase 4 native decryptor)")
    else:
        print(f"[manifest_zip_patcher] Step 17D — encrypted {encrypted_count}/{str_count} strings")

    # ── Step 17E — inject fake encrypted blocks after real strings ────────────
    fake_blocks = bytearray()
    n_fakes = random.randint(3, 8)
    for _ in range(n_fakes):
        fake_blocks.extend(fake_gcm_block())
    print(f"[manifest_zip_patcher] Step 17E — injected {n_fakes} fake encrypted blocks "
          f"({len(fake_blocks)} bytes)")

    # ── Rebuild string pool ───────────────────────────────────────────────────
    style_data = b''
    if style_count > 0 and styles_start > 0:
        style_abs  = SP + styles_start
        style_data = bytes(data[style_abs : SP + sp_chunk_size])

    new_offsets_bytes = b''.join(struct.pack('<I', o) for o in new_offsets)
    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_styles_start  = (new_strings_start + len(new_str_data) + len(fake_blocks)) if style_count > 0 else 0
    new_sp_chunk_size = (sp_hdr_size + len(new_offsets_bytes)
                         + len(new_str_data) + len(fake_blocks) + len(style_data))

    new_sp_hdr = bytearray(sp_hdr_size)
    struct.pack_into('<H', new_sp_hdr,  0, STRING_POOL_TYPE)
    struct.pack_into('<H', new_sp_hdr,  2, sp_hdr_size)
    struct.pack_into('<I', new_sp_hdr,  4, new_sp_chunk_size)
    struct.pack_into('<I', new_sp_hdr,  8, str_count)
    struct.pack_into('<I', new_sp_hdr, 12, style_count)
    struct.pack_into('<I', new_sp_hdr, 16, flags)
    struct.pack_into('<I', new_sp_hdr, 20, new_strings_start)
    struct.pack_into('<I', new_sp_hdr, 24, new_styles_start)

    new_sp = (bytes(new_sp_hdr) + new_offsets_bytes
              + bytes(new_str_data) + bytes(fake_blocks) + style_data)

    rest_off    = SP + sp_chunk_size
    rest        = bytes(data[rest_off:])
    new_total   = 8 + len(new_sp) + len(rest)
    result      = bytearray(data[:8])
    struct.pack_into('<I', result, 4, new_total)   # patch file total size in AXML header
    result.extend(new_sp)
    result.extend(rest)

    # ── Step 17F — append random binary padding ───────────────────────────────
    pad_len = random.randint(PAD_MIN, PAD_MAX)
    result.extend(secrets.token_bytes(pad_len))
    print(f"[manifest_zip_patcher] Step 17F — appended {pad_len} bytes manifest padding")

    return bytes(result)


# ── APK patcher ───────────────────────────────────────────────────────────────

def patch_apk(apk_in: str, apk_out: str, aes_key_hex: str, skip_17d: bool = False):
    aes_key = bytes.fromhex(aes_key_hex) if aes_key_hex else None

    SUPPORTED_COMPRESS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

    # Read entire APK as raw bytes — needed to copy non-standard entries verbatim
    with open(apk_in, 'rb') as f:
        raw_apk = f.read()

    tmp = apk_out + '.mzp_tmp'
    with zipfile.ZipFile(apk_in, 'r') as zin,          zipfile.ZipFile(tmp, 'w', allowZip64=False) as zout:
        for item in zin.infolist():
            if item.compress_type not in SUPPORTED_COMPRESS:
                # Non-standard compression (e.g. type 2032 from Step 17B).
                # Cannot decompress — copy raw compressed bytes verbatim from
                # the original APK binary using the entry's known offset + size.
                # Locate data start: skip LFH (30 bytes + fname + extra)
                lfh_off = item.header_offset
                fname_len = struct.unpack_from('<H', raw_apk, lfh_off + 26)[0]
                extra_len = struct.unpack_from('<H', raw_apk, lfh_off + 28)[0]
                data_off  = lfh_off + 30 + fname_len + extra_len
                raw_data  = raw_apk[data_off : data_off + item.compress_size]
                # Build new ZipInfo preserving all original metadata
                zi = zipfile.ZipInfo(item.filename)
                zi.compress_type   = item.compress_type
                zi.file_size       = item.file_size
                zi.compress_size   = item.compress_size
                zi.CRC             = item.CRC
                zi.date_time       = item.date_time
                zi.create_system   = item.create_system
                zi.extract_version = item.extract_version
                zi.flag_bits       = item.flag_bits
                zi.volume          = item.volume
                zi.internal_attr   = item.internal_attr
                zi.external_attr   = item.external_attr
                # Write using low-level ZipFile internals to avoid decompression
                zout._write_fileheader(zi)
                zout.fp.write(raw_data)
                zout._didModify = True
                zout.filelist.append(zi)
                zout.NameToInfo[zi.filename] = zi
                continue

            data = zin.read(item.filename)
            if item.filename == 'AndroidManifest.xml':
                print(f"[manifest_zip_patcher] Patching AndroidManifest.xml "
                      f"({len(data)} bytes)...")
                data = patch_axml(data, aes_key, skip_17d=skip_17d)
                item.compress_type = zipfile.ZIP_STORED
                print(f"[manifest_zip_patcher] Patched manifest: {len(data)} bytes")
            zout.writestr(item, data)

    os.replace(tmp, apk_out)
    print(f"[manifest_zip_patcher] \u2705 Done: {apk_out}")

