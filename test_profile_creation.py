"""
test_profile_creation.py — reproduces and verifies the fix for the bug
the user actually hit: creating a profile through the web UI wrote a
registry entry only — no identity (no passphrase field existed at all),
and nothing was ever listening on the new profile's port, so the link
shown in the UI just connection-refused. You couldn't use a profile you
just created.

This drives the real HTTP API end-to-end: create a profile with a
passphrase, confirm a background process actually gets spawned and
comes up on its own port, and confirm the identity it was given can
actually be unlocked there with that same passphrase.

Run: python3 test_profile_creation.py
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import requests

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def main():
    repo = os.path.dirname(os.path.abspath(__file__))
    tmp_home = tempfile.mkdtemp(prefix="enclave_home_")
    env = os.environ.copy()
    env["HOME"] = tmp_home
    env["PYTHONUNBUFFERED"] = "1"

    PARENT_PORT = 60101
    parent = subprocess.Popen(
        ["python3", "web.py", "--port", str(PARENT_PORT)],
        cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=os.setsid,
    )
    child_proc_found = None

    try:
        base = f"http://127.0.0.1:{PARENT_PORT}"
        up = False
        for _ in range(30):
            try:
                if requests.get(f"{base}/api/health", timeout=1).status_code == 200:
                    up = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.3)
        check("parent web.py came up", up)

        r = requests.get(f"{base}/")
        token = re.search(r'CSRF_TOKEN\s*=\s*"([^"]+)"', r.text).group(1)
        headers = {"X-Enclave-CSRF": token}

        # --- Reproduce the exact original bug: no passphrase field ---
        r = requests.post(f"{base}/api/profiles", json={"name": "nopass_test"}, headers=headers)
        check("creating a profile with NO passphrase is now rejected (was silently allowed before)",
              r.status_code == 400)

        # --- The real fix: create with a passphrase, get something usable back ---
        r = requests.post(f"{base}/api/profiles",
                          json={"name": "realprofile", "passphrase": "testpass456"},
                          headers=headers)
        check("creating a profile WITH a passphrase succeeds", r.status_code == 201)
        profile = r.json()
        check("response reports the background process started",
              profile.get("process_started") is True)
        new_port = profile.get("web_port")
        check("response includes the new profile's web_port", bool(new_port))

        # --- Is the URL shown in the UI actually alive? (the literal bug report) ---
        child_base = f"http://127.0.0.1:{new_port}"
        child_up = False
        for _ in range(30):
            try:
                if requests.get(f"{child_base}/api/health", timeout=1).status_code == 200:
                    child_up = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.3)
        check("the new profile's own URL is ACTUALLY reachable (was connection-refused before)",
              child_up)

        # --- Can the passphrase we gave it actually unlock it? ---
        if child_up:
            r2 = requests.get(f"{child_base}/")
            child_token = re.search(r'CSRF_TOKEN\s*=\s*"([^"]+)"', r2.text).group(1)
            r3 = requests.post(f"{child_base}/api/node/start",
                               json={"passphrase": "testpass456"},
                               headers={"X-Enclave-CSRF": child_token})
            check("the identity we created can be unlocked with that passphrase, on the new profile's own process",
                  r3.status_code == 200 and r3.json().get("ok"))
            check("the new profile reports its own correct profile name",
                  requests.get(f"{child_base}/api/identity/status").json().get("profile") == "realprofile")

        # --- Duplicate name still correctly rejected (existing behavior, unaffected) ---
        r = requests.post(f"{base}/api/profiles",
                          json={"name": "realprofile", "passphrase": "whatever"},
                          headers=headers)
        check("duplicate profile name is still rejected", r.status_code == 409)

    finally:
        # Best-effort cleanup of the spawned child (start_new_session=True
        # means it's not in the parent's process group).
        try:
            subprocess.run(["pkill", "-f", "web.py --profile realprofile"], timeout=3)
        except Exception:
            pass
        os.killpg(os.getpgid(parent.pid), signal.SIGTERM)
        try:
            out, _ = parent.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(parent.pid), signal.SIGKILL)
            out = ""
        shutil.rmtree(tmp_home, ignore_errors=True)
        shutil.rmtree(os.path.join(repo, "storage"), ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        print(out[-2000:] if 'out' in dir() else '')
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
