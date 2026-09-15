"""
test_multi_profile.py — proves multiple Enclave profiles can genuinely run
at the same time on one device: separate processes, separate ports, and
mutual LAN discovery between them.

This exists because that claim looked true by code inspection (ports are
auto-allocated per profile in core/profiles.py) but wasn't true in practice
until two real bugs got fixed:

1. discovery.py used UDP broadcast + SO_REUSEPORT for its listen socket.
   On Linux, SO_REUSEPORT load-balances incoming datagrams across sockets
   sharing a port — the kernel delivers each packet to exactly ONE of
   them, not a copy to each. Two local profiles each only received
   roughly half of all announcements, non-deterministically; in repeated
   trials it was consistently "exactly one side sees the other," never
   both. Switched to UDP multicast, which actually fans a single sent
   packet out to every socket that joined the group — verified that
   property directly before touching the app code at all.

2. core/network/router.py, discovery.py, and transport.py all use
   logging.getLogger("network"), which was never connected to any
   handler anywhere. main.py unconditionally initializes a LogStore for
   the DEFAULT profile at import time, before cmd_run's own
   _init_stores(args.profile) call for whatever profile was actually
   requested — so even after wiring "network" up to propagate to the
   root logger, a one-shot "configure root once" flag left root
   permanently pointed at the default profile's log file, not whichever
   profile ended up active. The underlying discovery mechanism was
   correct the whole time (peer_store genuinely got populated) — only
   its own logging was invisible, which is exactly the kind of thing you
   only find by checking ground truth (the actual stored peer data)
   instead of trusting a log line as a proxy for it, which is why this
   test checks both.

Spins up two real `python3 main.py run` subprocesses under a shared,
sandboxed HOME — not mocks, not in-process shortcuts — because that's
the literal scenario being verified: two terminals, two profiles, one
machine.

Run: python3 test_multi_profile.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

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

    profiles_spec = [
        ("alice", 57101, 57201, "alicepass123"),
        ("bob",   57102, 57202, "bobpass123"),
    ]

    setup = subprocess.run(
        ["python3", "-c", f"""
import sys; sys.path.insert(0, '.')
from core import profiles
from core.identity.key_manager import IdentityManager
for name, tport, wport, pw in {profiles_spec!r}:
    p = profiles.create_profile(name, username=name, transport_port=tport, web_port=wport)
    im = IdentityManager(storage_dir=p["data_dir"] + "/identity")
    im.generate_new_identity()
    im.save_identity(passphrase=pw)
    print(name, im.get_user_id())
"""],
        cwd=repo, env=env, capture_output=True, text=True,
    )
    check("both profiles + identities created", setup.returncode == 0)
    ids = dict(line.split() for line in setup.stdout.strip().split("\n"))

    procs = {}
    for name, _tport, _wport, passphrase in profiles_spec:
        procs[name] = subprocess.Popen(
            ["python3", "main.py", "run", "--profile", name,
             "--passphrase", passphrase, "--ci"],
            cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid,
        )

    try:
        time.sleep(6)
        check("both profiles running concurrently — no port collision",
              all(p.poll() is None for p in procs.values()))

        for p in procs.values():
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        clean = True
        for p in procs.values():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                clean = False
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        check("both processes shut down cleanly on SIGTERM", clean)

        # Ground truth first: the actual on-disk peer_store, not logs.
        def load_peers(profile):
            path = os.path.join(tmp_home, ".enclave-messenger", "profiles",
                                 profile, "peers.json")
            with open(path) as f:
                data = json.load(f)
            return data.values() if isinstance(data, dict) else data

        alice_peers = list(load_peers("alice"))
        bob_peers = list(load_peers("bob"))
        check("alice's peer_store genuinely contains bob",
              any(p.get("user_id") == ids["bob"] for p in alice_peers))
        check("bob's peer_store genuinely contains alice",
              any(p.get("user_id") == ids["alice"] for p in bob_peers))

        # Then logging visibility, which is its own thing worth checking now
        # that it's actually fixed.
        alice_log = open(os.path.join(repo, "storage", "logs", "enclave-alice.log")).read()
        bob_log = open(os.path.join(repo, "storage", "logs", "enclave-bob.log")).read()
        check("alice's log shows she discovered a peer", "saw peer" in alice_log)
        check("bob's log shows he discovered a peer", "saw peer" in bob_log)

    finally:
        for p in procs.values():
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        shutil.rmtree(tmp_home, ignore_errors=True)
        shutil.rmtree(os.path.join(repo, "storage"), ignore_errors=True)

    test_bind_mode_coherence()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


def test_bind_mode_coherence():
    """
    Discovery (broadcasting your presence + real LAN IP) and Transport
    (actually accepting connections) must always agree. They're derived
    from one setting for exactly this reason.

    This regressed once already, in the worst possible way: the fix was
    applied to __init__ (computing _lan_enabled) but not to start()/stop()
    (actually using it), so the flag existed and did nothing. Everything
    compiled, every other test passed, and network_bind=host still
    broadcast your IP to the whole LAN while refusing every connection.
    A half-applied fix to a two-sided invariant is worse than no fix,
    because it looks done. Hence this test.
    """
    import tempfile as _tf
    from core.identity.key_manager import IdentityManager
    from core.storage import ConfigStore, ChatStore, PeerStore
    from core.network.router import Node

    def mk(label, tport, bind_mode=None):
        d = os.path.join(_tf.mkdtemp(), label)
        os.makedirs(d)
        im = IdentityManager(storage_dir=os.path.join(d, "identity"))
        im.generate_new_identity()
        cfg = ConfigStore(base_dir=d)
        cfg.set_setting("network_port", tport)
        if bind_mode:
            cfg.set_setting("network_bind", bind_mode)
        return Node(im, cfg, PeerStore(base_dir=d), ChatStore(base_dir=d))

    import socket as _socket
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    probe.connect(("8.8.8.8", 80))
    real_ip = probe.getsockname()[0]
    probe.close()

    def can_connect(ip, port, timeout=1.5):
        s = _socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True
        except Exception:
            return False
        finally:
            s.close()

    n1 = mk("coherence_default", 61301)
    check("default: LAN enabled", n1._lan_enabled is True)
    n1.start()
    time.sleep(0.5)
    check("default: reachable on the real LAN IP (matches what discovery advertises)",
          can_connect(real_ip, 61301))
    n1.stop()

    n2 = mk("coherence_host", 61302, bind_mode="host")
    check("network_bind=host: LAN disabled", n2._lan_enabled is False)
    n2.start()
    time.sleep(0.5)
    check("host mode: NOT reachable on the real LAN IP",
          not can_connect(real_ip, 61302))
    check("host mode: still reachable on loopback (that's the point of the mode)",
          can_connect("127.0.0.1", 61302))
    # Would raise RuntimeError joining never-started threads without the
    # matching guard in stop().
    n2.stop()
    check("host mode stops cleanly without a RuntimeError", True)


if __name__ == "__main__":
    sys.exit(main())
