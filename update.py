#!/usr/bin/env python3
"""
Enclave-Messenger update verifier and applier.
Usage: python update.py <path-to-update-directory>
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys

# Path to the embedded public key (same directory as this script)
PUBLIC_KEY = os.path.join(os.path.dirname(__file__), "public.pem")


def verify_and_apply(update_dir):
    manifest_path = os.path.join(update_dir, "manifest.json")
    sig_path = os.path.join(update_dir, "manifest.sig")

    if not os.path.exists(manifest_path) or not os.path.exists(sig_path):
        raise FileNotFoundError("manifest.json or manifest.sig missing from update directory.")

    # 1. Verify signature
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", PUBLIC_KEY,
         "-signature", sig_path, manifest_path],
        capture_output=True, text=True
    )

    if "Verified OK" not in result.stdout:
        raise PermissionError("Invalid signature — update rejected. Do not apply.")

    print("Signature verified ✅")

    # 2. Verify file hashes
    manifest = json.load(open(manifest_path))
    for fname, expected_hash in manifest.items():
        fpath = os.path.join(update_dir, fname)
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Missing file in update: {fname}")
        actual = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
        if actual != expected_hash:
            raise ValueError(f"Hash mismatch for {fname} — update rejected.")
        print(f"  Verified: {fname}")

    print("All hashes verified ✅")

    # 3. Apply update
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for fname in manifest:
        src = os.path.join(update_dir, fname)
        dst = os.path.join(base_dir, fname)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        print(f"  Applied: {fname}")

    print("\nUpdate applied ✅ — restart Enclave to take effect.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python update.py <update-directory>")
        sys.exit(1)
    try:
        verify_and_apply(sys.argv[1])
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
