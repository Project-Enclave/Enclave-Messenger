"""
test_update.py — real tests for update.py's signature verification and
path-traversal guard. Uses a real openssl keypair and real subprocess
invocations of update.py itself, not mocks.

Run: python3 test_update.py
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def main():
    repo = os.path.dirname(os.path.abspath(__file__))
    tmp = tempfile.mkdtemp()
    appdir = os.path.join(tmp, "app")
    os.makedirs(appdir)
    shutil.copy(os.path.join(repo, "update.py"), os.path.join(appdir, "update.py"))

    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                    "-out", os.path.join(tmp, "priv.pem"),
                    "-pkeyopt", "rsa_keygen_bits:2048"], capture_output=True)
    subprocess.run(["openssl", "rsa", "-pubout", "-in", os.path.join(tmp, "priv.pem"),
                    "-out", os.path.join(appdir, ".public.pem")], capture_output=True)

    def make_update(files):
        upd = tempfile.mkdtemp()
        manifest = {}
        for fname, content in files.items():
            path = os.path.join(upd, fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            manifest[fname] = hashlib.sha256(content.encode()).hexdigest()
        mpath = os.path.join(upd, "manifest.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.path.join(tmp, "priv.pem"),
                        "-out", os.path.join(upd, "manifest.sig"), mpath], capture_output=True)
        return upd

    def sign_manifest(upd_dir, manifest_path):
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.path.join(tmp, "priv.pem"),
                        "-out", os.path.join(upd_dir, "manifest.sig"), manifest_path],
                       capture_output=True)

    # --- valid update applies cleanly ---
    upd1 = make_update({"newfile.txt": "hello world"})
    r = subprocess.run([sys.executable, os.path.join(appdir, "update.py"), upd1],
                       capture_output=True, text=True, cwd=appdir)
    check("valid signed update applies successfully", r.returncode == 0)
    check("file actually got written", os.path.exists(os.path.join(appdir, "newfile.txt")))

    # --- tampered manifest (bad signature) rejected ---
    upd2 = make_update({"newfile2.txt": "hello"})
    with open(os.path.join(upd2, "manifest.json"), "w") as f:
        json.dump({"newfile2.txt": "0" * 64, "injected.txt": "0" * 64}, f)  # tamper post-sign
    r = subprocess.run([sys.executable, os.path.join(appdir, "update.py"), upd2],
                       capture_output=True, text=True, cwd=appdir)
    check("tampered manifest rejected (nonzero exit)", r.returncode != 0)
    check("rejection message mentions signature",
          "signature" in r.stdout.lower() or "signature" in r.stderr.lower())
    check("no injected file was written", not os.path.exists(os.path.join(appdir, "injected.txt")))

    # --- path traversal in a validly-signed manifest rejected ---
    upd3 = tempfile.mkdtemp()
    target_rel = "../../../tmp/enclave_test_traversal_target.txt"
    target_abs = os.path.join(upd3, target_rel)
    os.makedirs(os.path.dirname(target_abs), exist_ok=True)
    with open(target_abs, "w") as f:
        f.write("pwned")
    manifest_path = os.path.join(upd3, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump({target_rel: hashlib.sha256(b"pwned").hexdigest()}, f)
    sign_manifest(upd3, manifest_path)

    real_target = "/tmp/enclave_test_traversal_target.txt"
    if os.path.exists(real_target):
        os.remove(real_target)

    r = subprocess.run([sys.executable, os.path.join(appdir, "update.py"), upd3],
                       capture_output=True, text=True, cwd=appdir)
    check("path-traversal manifest entry rejected (nonzero exit)", r.returncode != 0)
    check("rejection message mentions unsafe path", "unsafe path" in r.stdout.lower())
    check("traversal target was never written outside appdir", not os.path.exists(real_target))

    shutil.rmtree(tmp, ignore_errors=True)
    if os.path.exists(real_target):
        os.remove(real_target)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
