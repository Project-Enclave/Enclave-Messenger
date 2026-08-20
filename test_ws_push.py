"""
test_ws_push.py — real end-to-end test of the WebSocket live-push
mechanism: does an inbound message actually reach a connected browser
tab without polling, not just "does the code look wired up right."

Spawns a real web.py server, connects a genuine WebSocket client, POSTs
an inbound envelope to the real transport endpoint (the same path a
real peer's Node.send() uses), and checks whether the connected client
receives a push event.

Requires the `websockets` package (test-only, not an app dependency):
    pip install websockets

Run: python3 test_ws_push.py
"""
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import requests
import websockets

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")

WEB_PORT = 59931
TRANSPORT_PORT = 59932


async def main():
    tmp_home = tempfile.mkdtemp(prefix="enclave_home_")
    env = os.environ.copy()
    env["HOME"] = tmp_home
    env["PYTHONUNBUFFERED"] = "1"
    repo = os.path.dirname(os.path.abspath(__file__))

    setup = subprocess.run(["python3", "-c", f"""
import sys; sys.path.insert(0, '.')
from core import profiles
from core.identity.key_manager import IdentityManager
p = profiles.create_profile("alice", username="alice", transport_port={TRANSPORT_PORT}, web_port={WEB_PORT})
im = IdentityManager(storage_dir=p["data_dir"] + "/identity")
im.generate_new_identity()
im.save_identity(passphrase="alicepass123")
print(im.get_user_id())
"""], cwd=repo, env=env, capture_output=True, text=True)
    check("profile + identity setup succeeded", setup.returncode == 0)
    alice_id = setup.stdout.strip()

    proc = subprocess.Popen(
        ["python3", "web.py", "--profile", "alice", "--port", str(WEB_PORT)],
        cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=os.setsid,
    )

    try:
        base = f"http://127.0.0.1:{WEB_PORT}"
        up = False
        for _ in range(30):
            try:
                if requests.get(f"{base}/api/health", timeout=1).status_code == 200:
                    up = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.3)
        check("web.py server came up", up)

        r = requests.get(f"{base}/")
        token = re.search(r'CSRF_TOKEN\s*=\s*"([^"]+)"', r.text).group(1)

        r = requests.post(f"{base}/api/node/start", json={"passphrase": "alicepass123"},
                           headers={"X-Enclave-CSRF": token})
        check("node started via the real HTTP flow", r.status_code == 200 and r.json().get("ok"))

        # Connect a REAL websocket client — this is the actual transport
        # a browser tab uses, not a mock.
        async with websockets.connect(f"ws://127.0.0.1:{WEB_PORT}/ws") as ws:
            init_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            init = json.loads(init_raw)
            check("received an 'init' frame on connect", init.get("event") == "init")

            # Deliver an inbound message via the REAL transport endpoint —
            # this is the exact path a real peer's Node.send() posts to.
            # Sender is a brand-new identity alice has never seen before
            # (TOFU path — no signature needed, matches _on_inbound's
            # actual first-contact behavior).
            bob_id = "b" * 43
            envelope = {
                "from": bob_id,
                "chat_id": bob_id,
                "token": "fake-ciphertext-token-for-push-test",
                "ts": "2026-08-18T00:00:00+00:00",
            }
            r = requests.post(f"http://127.0.0.1:{TRANSPORT_PORT}/inbound",
                               json=envelope, timeout=3)
            check("inbound envelope accepted by the real transport endpoint",
                  r.status_code == 200)

            # The actual claim under test: does the WS client get pushed
            # a 'new_message' event WITHOUT polling?
            try:
                push_raw = await asyncio.wait_for(ws.recv(), timeout=5)
                push = json.loads(push_raw)
                check("WS client received a push event after inbound message",
                      push.get("event") == "new_message")
                if push.get("event") == "new_message":
                    check("pushed event has the correct sender_id",
                          push.get("sender_id") == bob_id)
            except asyncio.TimeoutError:
                check("WS client received a push event after inbound message", False)

    finally:
        os.killpg(os.getpgid(proc.pid), 15)
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), 9)
            out = ""
        shutil.rmtree(tmp_home, ignore_errors=True)
        shutil.rmtree(os.path.join(repo, "storage"), ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        print("\n=== server output (tail) ===")
        print(out[-3000:])
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
