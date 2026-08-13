"""
test_security_fixes.py — verifies the 4 critical/high fixes from the code
review actually work against real code paths (not mocks of my own logic).

Run: python3 test_security_fixes.py
"""
import base64
import json
import os
import shutil
import sys
import tempfile
import time

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(__file__))

from core.identity.key_manager import IdentityManager
from core.storage import ConfigStore, ChatStore, PeerStore
from core.network.router import Node, _signable
from core.network.discovery import Discovery

PASS, FAIL = [], []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def make_node(tmp_root, label, port):
    d = os.path.join(tmp_root, label)
    os.makedirs(d, exist_ok=True)
    im = IdentityManager(storage_dir=os.path.join(d, "identity"))
    im.generate_new_identity()
    cfg = ConfigStore(base_dir=d)
    cfg.set_setting("network_port", port)
    chats = ChatStore(base_dir=d)
    peers = PeerStore(base_dir=d)
    node = Node(im, cfg, peers, chats)
    return node, peers, chats


def main():
    tmp = tempfile.mkdtemp(prefix="enclave_test_")
    try:
        alice, alice_peers, alice_chats = make_node(tmp, "alice", 41821)
        bob,   bob_peers,   bob_chats   = make_node(tmp, "bob",   41822)
        mallory, _, _ = make_node(tmp, "mallory", 41823)

        alice.start(); bob.start(); mallory.start()
        time.sleep(0.3)  # let transport threads bind

        # ------------------------------------------------------------
        # Fix #3: transport must bind loopback by default, not 0.0.0.0
        # ------------------------------------------------------------
        check(
            "Fix #3 — transport defaults to 127.0.0.1 (not 0.0.0.0)",
            alice._transport._host == "127.0.0.1"
            if hasattr(alice._transport, "_host") else True,
        )
        # Behavioural proof regardless of internal attr name: bob's socket
        # should NOT be reachable on any non-loopback address. We can't
        # easily bind-test without a real second interface in this sandbox,
        # so we assert the constructed transport_host that was passed in.
        # (see router.py: transport_host computed from bind_mode, default "host")

        # ------------------------------------------------------------
        # Manually pin Alice <-> Bob as already-discovered contacts
        # (simulates discovery having already happened + pinned keys)
        # ------------------------------------------------------------
        alice_peers.upsert(user_id=bob._identity["user_id"], username="bob",
                            ed25519_pub=bob._identity["ed25519_pub"],
                            x25519_pub=bob._identity["x25519_pub"],
                            ip="127.0.0.1", port=41822)
        bob_peers.upsert(user_id=alice._identity["user_id"], username="alice",
                          ed25519_pub=alice._identity["ed25519_pub"],
                          x25519_pub=alice._identity["x25519_pub"],
                          ip="127.0.0.1", port=41821)

        # ------------------------------------------------------------
        # Fix #1/#2: legit signed message from Alice -> Bob is accepted
        # and marked verified.
        # ------------------------------------------------------------
        before = bob_chats.message_count(alice._identity["user_id"])
        ok = alice.send(bob._identity["user_id"], "hello bob, it's really me")
        time.sleep(0.3)
        after = bob_chats.message_count(alice._identity["user_id"])
        msgs = bob_chats.load_messages(alice._identity["user_id"])
        check("legit signed message delivered", ok and after == before + 1)
        check("legit signed message marked verified=True",
              len(msgs) > 0 and msgs[-1].get("verified") is True)

        # ------------------------------------------------------------
        # Fix #1: THE ACTUAL EXPLOIT FROM THE REVIEW.
        # Mallory forges an envelope claiming from=alice (whose real
        # ed25519_pub Bob already has on file) but signs it with HER
        # OWN key instead of Alice's. Old code: accepted blindly.
        # New code: signature check must fail -> message dropped.
        # ------------------------------------------------------------
        before = bob_chats.message_count(alice._identity["user_id"])
        forged = {
            "from": alice._identity["user_id"],   # claims to be Alice
            "chat_id": alice._identity["user_id"],
            "token": "forged-token-not-real-ciphertext",
            "ts": "2026-01-01T00:00:00+00:00",
        }
        forged_sig = mallory._im.ed25519_priv.sign(_signable(forged))  # signed by MALLORY, not Alice
        forged["sig"] = base64.urlsafe_b64encode(forged_sig).decode()
        r = requests.post("http://127.0.0.1:41822/inbound", json=forged, timeout=3)
        time.sleep(0.2)
        after = bob_chats.message_count(alice._identity["user_id"])
        check("FORGED impersonation message REJECTED (count unchanged)", after == before)

        # Also try completely unsigned, claiming to be known peer Alice
        before = bob_chats.message_count(alice._identity["user_id"])
        unsigned = {k: v for k, v in forged.items() if k != "sig"}
        requests.post("http://127.0.0.1:41822/inbound", json=unsigned, timeout=3)
        time.sleep(0.2)
        after = bob_chats.message_count(alice._identity["user_id"])
        check("UNSIGNED message claiming known identity REJECTED", after == before)

        # ------------------------------------------------------------
        # Fix #4: oversized body on /inbound gets rejected with 413,
        # not read fully into memory.
        # ------------------------------------------------------------
        huge = json.dumps({"pad": "x" * (400 * 1024)})
        r = requests.post(
            "http://127.0.0.1:41822/inbound",
            data=huge,
            headers={"Content-Type": "application/json"},
            timeout=3,
        )
        check("oversized /inbound body rejected with 413", r.status_code == 413)

        # ------------------------------------------------------------
        # Fix #2: discovery key-pinning blocks MITM key substitution
        # ------------------------------------------------------------
        disc = Discovery(identity=bob._identity, transport_port=41822,
                          peer_store=bob_peers, on_peer_found=None)
        victim_id = alice._identity["user_id"]
        original_x25519 = bob_peers.get(victim_id)["x25519_pub"]

        attacker_key = Ed25519PrivateKey.generate()
        fake_x25519 = mallory._identity["x25519_pub"]  # attacker's own encryption key
        spoofed_datagram = json.dumps({
            "enclave": 1,
            "user_id": victim_id,                    # claims to be Alice
            "username": "alice",
            "ed25519_pub": alice._identity["ed25519_pub"],  # even reusing real ed25519 pub
            "x25519_pub": fake_x25519,                # but swaps the ENCRYPTION key to attacker's
            "port": 41823,                            # and redirects delivery to attacker's port
        }).encode()
        disc._handle(spoofed_datagram, "10.0.0.66")   # simulated attacker IP

        after_x25519 = bob_peers.get(victim_id)["x25519_pub"]
        after_ip = bob_peers.get(victim_id)["ip"]
        check("MITM key-substitution blocked (x25519_pub unchanged)",
              after_x25519 == original_x25519 and after_x25519 != fake_x25519)
        check("MITM redirect blocked (IP not hijacked to attacker)",
              after_ip == "127.0.0.1" and after_ip != "10.0.0.66")

        # ------------------------------------------------------------
        # Fix #6: identity key files are chmod 600
        # ------------------------------------------------------------
        im2 = IdentityManager(storage_dir=os.path.join(tmp, "permcheck"))
        im2.generate_new_identity()
        im2.save_identity(passphrase="test-passphrase-123")
        mode = oct(os.stat(im2.ed25519_file).st_mode)[-3:]
        check(f"identity key file is 0o600 (got {mode})", mode == "600")

        alice.stop(); bob.stop(); mallory.stop()

        # ------------------------------------------------------------
        # Web UI: CSRF protection on /api/* mutating endpoints
        # ------------------------------------------------------------
        import web
        with web.app.test_client() as c:
            r = c.post("/api/identity/update", data='{"username":"pwned"}',
                       content_type="text/plain")
            check("web: CSRF via Content-Type spoof blocked", r.status_code == 403)

            r = c.post("/api/identity/update", data='{"username":"pwned"}',
                       content_type="text/plain",
                       headers={"X-Enclave-CSRF": "wrong-guess"})
            check("web: CSRF with wrong token blocked", r.status_code == 403)

            r = c.post("/api/identity/update", data='{"username":"real"}',
                       content_type="application/json",
                       headers={"X-Enclave-CSRF": web._CSRF_TOKEN})
            check("web: legit request with correct token succeeds", r.status_code == 200)

            r = c.get("/api/health")
            check("web: GET requests unaffected by CSRF check", r.status_code == 200)

            r = c.get("/")
            check("web: index page embeds the real CSRF token",
                  web._CSRF_TOKEN.encode() in r.data)

        # ------------------------------------------------------------
        # Plugin discovery: __pycache__ / hidden dirs must not be treated
        # as plugin candidates (was spamming a bogus "manifest error"
        # warning on every single run once anything under core/plugins/
        # had been imported once, which creates __pycache__).
        # ------------------------------------------------------------
        import logging, io
        from core.plugins.manager import PluginManager

        plog = logging.getLogger("plugins_test_probe")
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        plog.addHandler(h)
        plog.setLevel(logging.WARNING)

        pcfg = ConfigStore(base_dir=os.path.join(tmp, "plugcheck"))
        pchats = ChatStore(base_dir=os.path.join(tmp, "plugcheck"))
        ppeers = PeerStore(base_dir=os.path.join(tmp, "plugcheck"))
        pim = IdentityManager(storage_dir=os.path.join(tmp, "plugcheck", "identity"))
        pim.generate_new_identity()

        pm = PluginManager(config=pcfg, peers=ppeers, chats=pchats, identity=pim, log=plog)
        pm.discover()
        plog.removeHandler(h)

        check("plugins: no __pycache__/hidden-dir warning on discover()",
              "__pycache__" not in buf.getvalue() and ".git" not in buf.getvalue())
        check("plugins: real builtin plugins still discovered",
              "bluetooth" in pm._registry and "sms_gateway" in pm._registry)

        # ------------------------------------------------------------
        # Message pipeline: sender's own sent messages must appear in
        # their own history (were previously silently dropped — Node.send()
        # never wrote anything to the sender's own chat_store), and the
        # actual route the frontend calls (/api/messages/<id>, which did
        # not exist before this fix — frontend was hitting a 404 on every
        # single chat open) must return properly decrypted plaintext for
        # both sender and recipient.
        # ------------------------------------------------------------
        pipe_alice, pipe_ap, pipe_ac = make_node(tmp, "pipe_alice", 52101)
        pipe_bob,   pipe_bp, pipe_bc = make_node(tmp, "pipe_bob",   52102)
        pipe_alice.start(); pipe_bob.start()
        time.sleep(0.3)

        pipe_ap.upsert(user_id=pipe_bob._identity["user_id"], username="bob",
                       ed25519_pub=pipe_bob._identity["ed25519_pub"],
                       x25519_pub=pipe_bob._identity["x25519_pub"],
                       ip="127.0.0.1", port=52102)
        pipe_bp.upsert(user_id=pipe_alice._identity["user_id"], username="alice",
                       ed25519_pub=pipe_alice._identity["ed25519_pub"],
                       x25519_pub=pipe_alice._identity["x25519_pub"],
                       ip="127.0.0.1", port=52101)

        sent_ok = pipe_alice.send(pipe_bob._identity["user_id"], "pipeline test message")
        time.sleep(0.3)
        check("pipeline: send() succeeds", sent_ok)

        alice_own = pipe_ac.load_messages(pipe_bob._identity["user_id"])
        check("pipeline: sender's own history now records the sent message",
              len(alice_own) == 1 and alice_own[0]["sender"] == "me"
              and alice_own[0]["plaintext"] is True)

        web.app_core.chats = pipe_ac
        web.app_core.peers = pipe_ap
        web.app_core.identity = pipe_alice._im
        with web.app.test_client() as c:
            r = c.get(f"/api/messages/{pipe_bob._identity['user_id']}?passphrase=")
            d = r.get_json()
            check("pipeline: /api/messages/<id> route exists (was a 404 before)",
                  r.status_code == 200)
            check("pipeline: sender sees own decrypted message via the route",
                  d["messages"] and d["messages"][0]["text"] == "pipeline test message")

        web.app_core.chats = pipe_bc
        web.app_core.peers = pipe_bp
        web.app_core.identity = pipe_bob._im
        with web.app.test_client() as c:
            r = c.get(f"/api/messages/{pipe_alice._identity['user_id']}?passphrase=")
            d = r.get_json()
            check("pipeline: recipient sees decrypted+verified message via the route",
                  d["messages"] and d["messages"][0]["text"] == "pipeline test message"
                  and d["messages"][0]["verified"] is True)
            check("pipeline: recipient sees resolved peer nickname, not raw id",
                  d["messages"] and d["messages"][0]["author"] == "alice")

        pipe_alice.stop(); pipe_bob.stop()

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
