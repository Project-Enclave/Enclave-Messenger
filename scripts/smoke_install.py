#!/usr/bin/env python3
"""
Smoke-test an INSTALLED Enclave Messenger: a pipx/pip install (`pe-em`) or the
PyInstaller executable. Used by CI on Linux, macOS and Windows.

    python scripts/smoke_install.py pe-em
    python scripts/smoke_install.py ./dist/enclave-messenger

It runs with a throw-away ENCLAVE_HOME and a throw-away working directory, and checks:
  * --version / paths work and report the expected install kind
  * --help creates nothing on disk
  * `desktop --no-browser` really serves the UI (so templates were packaged)
  * the built-in plugins load (their sources/manifests were packaged)
  * data landed under ENCLAVE_HOME and nothing was written to the working directory
"""
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: smoke_install.py <command> [expected-install-kind]")
    cmd = sys.argv[1]
    # Resolve executable paths before subprocesses switch to the isolated cwd.
    # Leave bare commands such as `pe-em` for PATH lookup.
    if os.path.exists(cmd):
        cmd = os.path.abspath(cmd)
    expect_kind = sys.argv[2] if len(sys.argv) > 2 else None
    home = tempfile.mkdtemp(prefix="enclave_smoke_home_")
    cwd = tempfile.mkdtemp(prefix="enclave_smoke_cwd_")
    env = dict(os.environ, ENCLAVE_HOME=os.path.join(home, "h"), PYTHONUNBUFFERED="1")
    env.pop("PYTHONPATH", None)          # must work from the install alone
    env.pop("ENCLAVE_NO_LOGIN", None)    # the login gate must be ON, as for a real user
    failures = []

    def check(name, ok):
        print(("PASS  " if ok else "FAIL  ") + name)
        if not ok:
            failures.append(name)

    def run(*args):
        return subprocess.run([cmd, *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=120)

    r = run("--version")
    check("--version runs: " + r.stdout.strip(), r.returncode == 0 and r.stdout.startswith("pe-em "))
    if expect_kind:
        check(f"install kind is '{expect_kind}'", f"({expect_kind}," in r.stdout)
    r = run("--help")
    check("--help runs", r.returncode == 0 and "desktop" in r.stdout)
    r = run("paths", "--json")
    ok = r.returncode == 0
    if ok:
        d = json.loads(r.stdout)
        ok = d["override"] == env["ENCLAVE_HOME"]
    check("paths --json honours ENCLAVE_HOME", ok)
    check("--version/--help/paths wrote nothing to disk", not os.path.exists(env["ENCLAVE_HOME"]))

    port = free_port()
    app_log = tempfile.TemporaryFile(mode="w+b")
    proc = subprocess.Popen([cmd, "desktop", "--no-browser", "--port", str(port)], env=env, cwd=cwd,
                            stdout=app_log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    html = None
    try:
        for _ in range(120):
            if proc.poll() is not None:
                break
            try:
                html = urllib.request.urlopen(base + "/", timeout=1).read().decode()
                break
            except Exception:
                time.sleep(0.5)
        check("desktop serves the UI (templates are packaged)", bool(html) and "Enclave Messenger" in html)
        if html:
            m = re.search(r"CSRF_TOKEN\s*=\s*['\"]([^'\"]+)", html) or \
                re.search(r"csrf[^'\"]*['\"]([A-Za-z0-9_\-]{20,})['\"]", html, re.I)
            csrf = m.group(1) if m else ""
            try:
                urllib.request.urlopen(urllib.request.Request(base + "/api/plugins"), timeout=5)
                gated = False
            except urllib.error.HTTPError as e:
                gated = e.code == 401
            check("the API is behind the login (401 without a session)", gated)
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            req = urllib.request.Request(base + "/api/identity/generate", data=json.dumps({"passphrase": "smoke test passphrase"}).encode(),
                                         headers={"X-Enclave-CSRF": csrf, "Content-Type": "application/json"})
            created = json.loads(opener.open(req, timeout=20).read())
            check("first run: the person at this computer can create an identity (and is signed in)", bool(created.get("node_id")))
            plugins = json.loads(opener.open(urllib.request.Request(base + "/api/plugins"), timeout=5).read())["plugins"]
            ids = {p["id"] for p in plugins}
            check("built-in plugins load (sms_gateway, bluetooth)", {"sms_gateway", "bluetooth"} <= ids)
    finally:
        if proc.poll() is None:
            if os.name == "nt":
                # PyInstaller's one-file bootloader starts a child process on
                # Windows. Kill the whole tree so it cannot keep CI pipes or
                # the temporary web server alive after its parent exits.
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=False, timeout=10,
                    )
                except subprocess.TimeoutExpired:
                    proc.kill()
            else:
                proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        app_log.flush()
        if failures:
            app_log.seek(max(0, app_log.tell() - 600))
            tail = app_log.read().decode("utf-8", errors="replace")
            print("--- app output ---\n" + tail)
        app_log.close()

    check("data was created under ENCLAVE_HOME", os.path.isfile(os.path.join(env["ENCLAVE_HOME"], "config", "registry.json")))
    check("nothing was written to the working directory", os.listdir(cwd) == [])
    shutil.rmtree(home, ignore_errors=True)
    shutil.rmtree(cwd, ignore_errors=True)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")
    print("\nall smoke checks passed")


if __name__ == "__main__":
    main()
