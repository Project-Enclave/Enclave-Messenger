import os
import re
import shutil
import signal
import subprocess
import tempfile
import time

import requests

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def main():
    tmp_home = tempfile.mkdtemp(prefix="enclave_home_")
    env = os.environ.copy()
    env["HOME"] = tmp_home
    env["PYTHONUNBUFFERED"] = "1"
    repo = os.path.dirname(os.path.abspath(__file__))

    setup = subprocess.run(["python3", "-c", """
import sys; sys.path.insert(0, '.')
from core import profiles
from core.identity.key_manager import IdentityManager
for name, tport, wport, pw in [("alice", 59961, 59971, "p1"), ("bob", 59962, 59972, "p2")]:
    p = profiles.create_profile(name, username=name, transport_port=tport, web_port=wport)
    im = IdentityManager(storage_dir=p["data_dir"] + "/identity")
    im.generate_new_identity()
    im.save_identity(passphrase=pw)
"""], cwd=repo, env=env, capture_output=True, text=True)
    check("profile setup succeeded", setup.returncode == 0)

    procs = {}
    ports = {"alice": 59971, "bob": 59972}
    pws = {"alice": "p1", "bob": "p2"}
    for name, port in ports.items():
        procs[name] = subprocess.Popen(
            ["python3", "web.py", "--profile", name, "--port", str(port)],
            cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            preexec_fn=os.setsid,
        )

    try:
        up = {}
        ids = {}
        for name, port in ports.items():
            ok = False
            for _ in range(30):
                try:
                    if requests.get(f"http://127.0.0.1:{port}/api/health", timeout=1).status_code == 200:
                        ok = True
                        break
                except requests.exceptions.RequestException:
                    pass
                time.sleep(0.3)
            up[name] = ok

            base = f"http://127.0.0.1:{port}"
            r = requests.get(f"{base}/")
            match = re.search(r'CSRF_TOKEN\s*=\s*"([^"]+)"', r.text)
            if not match:
                ids[name] = None
                continue
            token = match.group(1)
            r = requests.post(f"{base}/api/node/start", json={"passphrase": pws[name]},
                               headers={"X-Enclave-CSRF": token})
            ids[name] = r.json().get("user_id") if r.status_code == 200 else None

        check("alice's web.py came up", up["alice"])
        check("bob's web.py came up", up["bob"])
        check("both processes still alive (no port collision)",
              all(p.poll() is None for p in procs.values()))
        check("both nodes started successfully via HTTP", bool(ids["alice"]) and bool(ids["bob"]))
        check("alice and bob have genuinely different, isolated identities",
              ids["alice"] != ids["bob"])

        ra = requests.get("http://127.0.0.1:59971/api/identity/status").json()
        rb = requests.get("http://127.0.0.1:59972/api/identity/status").json()
        check("each process's /api/identity/status reflects its own profile",
              ra.get("profile") == "alice" and rb.get("profile") == "bob")

    finally:
        for p in procs.values():
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        for p in procs.values():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        shutil.rmtree(tmp_home, ignore_errors=True)
        shutil.rmtree(os.path.join(repo, "storage"), ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
