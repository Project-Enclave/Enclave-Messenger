"""
test_at_rest.py - our own side of every conversation is encrypted on disk.

  * sent / failed / Bluetooth messages are sealed to our own key (no readable text in the files)
  * they still display, and failed ones can still be retried (the text is recovered by decrypting)
  * old plaintext history is upgraded in place, atomically, once
  * a locked identity refuses to write readable text instead of falling back to it
  * a stopped node really closes its port (it used to keep accepting and never answer)

Run:  python3 test/test_at_rest.py
"""
import _testenv  # noqa: F401
import os, shutil, socket, sys, tempfile, time
from pathlib import Path

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")

def all_bytes(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file())

def main():
    from enclave_messenger.core.crypto.e2e import E2EManager
    from enclave_messenger.core.storage import ChatStore
    from test_security_fixes import make_node
    import enclave_messenger.main as app_core

    tmp = tempfile.mkdtemp(prefix="enclave_rest_")
    try:
        print("\n[sent messages on disk]")
        alice, ap, ac = make_node(tmp, "alice", 53301)
        bob,   bp, bc = make_node(tmp, "bob",   53302)
        alice.start(); bob.start(); time.sleep(0.4)
        bid, aid = bob._identity["user_id"], alice._identity["user_id"]
        ap.upsert(user_id=bid, username="bob", ed25519_pub=bob._identity["ed25519_pub"],
                  x25519_pub=bob._identity["x25519_pub"], ip="127.0.0.1", port=53302)
        bp.upsert(user_id=aid, username="alice", ed25519_pub=alice._identity["ed25519_pub"],
                  x25519_pub=alice._identity["x25519_pub"], ip="127.0.0.1", port=53301)

        SECRET = "meet at the old bridge, 9pm SECRET-MARKER"
        check("delivered message is accepted", alice.send(bid, SECRET))
        time.sleep(0.3)
        rec = ac.load_messages(bid)
        check("stored record is an encrypted token, not plaintext", len(rec) == 1 and rec[0]["plaintext"] is False
              and SECRET not in rec[0]["token"] and E2EManager.is_e2e_token(rec[0]["token"]))
        check("the marker text appears NOWHERE in alice's data directory", b"SECRET-MARKER" not in all_bytes(Path(tmp) / "alice"))
        check("alice can read it back with her unlocked key",
              E2EManager(alice._im.x25519_priv).decrypt(rec[0]["token"]) == SECRET)
        check("bob's stored copy is separate and also unreadable on disk", b"SECRET-MARKER" not in all_bytes(Path(tmp) / "bob"))
        try:
            E2EManager(bob._im.x25519_priv).decrypt(rec[0]["token"]); leaked = True
        except Exception:
            leaked = False
        check("nobody else (not even bob's key) can open alice's own copy", not leaked)

        print("\n[display path]")
        app_core.chats, app_core.peers, app_core.identity = ac, ap, alice._im
        shown = app_core.get_messages_decrypted(bid, "")
        check("get_messages_decrypted() shows the sent message normally",
              len(shown) == 1 and shown[0]["text"] == SECRET and shown[0]["sender"] == "me" and shown[0]["encrypted"])

        print("\n[stopped node]")
        bob.stop(); time.sleep(0.3)
        sk = socket.socket(); sk.settimeout(1)
        check("a stopped node really closes its port (was: kept accepting, never answered)",
              sk.connect_ex(("127.0.0.1", 53302)) != 0)
        sk.close()
        t0 = time.time()
        check("sending to a stopped node fails fast instead of hanging", alice.send(bid, "to nobody") is False
              and time.time() - t0 < 4)

        print("\n[failed message + retry]")
        carol, cp, cc = make_node(tmp, "carol", 53303)       # known address, not started yet
        cid = carol._identity["user_id"]
        ap.upsert(user_id=cid, username="carol", ed25519_pub=carol._identity["ed25519_pub"],
                  x25519_pub=carol._identity["x25519_pub"], ip="127.0.0.1", port=53303)
        cp.upsert(user_id=aid, username="alice", ed25519_pub=alice._identity["ed25519_pub"],
                  x25519_pub=alice._identity["x25519_pub"], ip="127.0.0.1", port=53301)
        alice.send(cid, "second SECRET-MARKER")
        failed = [m for m in ac.load_messages(cid) if m.get("status") == "failed"][0]
        check("an undelivered message is sealed too", failed["plaintext"] is False and "SECRET-MARKER" not in failed["token"])
        check("...and no readable copy hit the disk", b"SECRET-MARKER" not in all_bytes(Path(tmp) / "alice"))
        carol.start(); time.sleep(0.5)
        check("retry decrypts our copy and delivers it", alice.retry_message(cid, failed["ts"]) is True)
        time.sleep(0.4)
        carol_texts = [E2EManager(carol._im.x25519_priv).decrypt(m["token"]) for m in cc.load_messages(aid)]
        check("carol received the retried text intact", "second SECRET-MARKER" in carol_texts)
        carol.stop()

        print("\n[upgrading old plaintext history]")
        old = tempfile.mkdtemp(prefix="enclave_old_")
        oc = ChatStore(old)
        oc.append_message("peerX", {"token": "OLD-PLAIN-1", "plaintext": True, "sender": "me", "ts": "T1", "status": "delivered"})
        oc.append_message("peerX", {"token": "tokenfromthem", "sender": "peerX", "ts": "T2"})
        oc.append_message("BT:AA:BB", {"token": "OLD-BT-RAW", "sender": "peer", "ts": "T3"})
        oc.append_message("BT:AA:BB", {"token": "OLD-BT-SENT", "sender": "me", "ts": "T4"})
        app_core.chats = oc
        n = app_core.seal_plaintext_history()
        check("three readable records were upgraded (the inbound token was left alone)", n == 3)
        check("no readable text remains in the old chat files", b"OLD-" not in all_bytes(Path(old)))
        txt = {m["ts"]: m for m in oc.load_messages("peerX") + oc.load_messages("BT:AA:BB")}
        dec = E2EManager(alice._im.x25519_priv)
        check("upgraded records decrypt back to the original text",
              dec.decrypt(txt["T1"]["token"]) == "OLD-PLAIN-1" and dec.decrypt(txt["T3"]["token"]) == "OLD-BT-RAW"
              and dec.decrypt(txt["T4"]["token"]) == "OLD-BT-SENT")
        check("delivery status and sender survive the upgrade", txt["T1"]["status"] == "delivered" and txt["T1"]["sender"] == "me")
        check("an inbound record is untouched", txt["T2"]["token"] == "tokenfromthem")
        check("running the upgrade again changes nothing", app_core.seal_plaintext_history() == 0)
        check("no temp files are left behind", not [p for p in Path(old).rglob("*.tmp")])

        print("\n[locked identity]")
        saved = app_core.identity.x25519_priv
        app_core.identity.x25519_priv = None
        try:
            app_core._seal("x", "c", "t"); refused = False
        except RuntimeError:
            refused = True
        check("a locked identity refuses to seal (no silent plaintext fallback)", refused)
        check("sealing history while locked is a harmless no-op", app_core.seal_plaintext_history() == 0)
        n_before = len(oc.load_messages("BT:AA:BB"))
        app_core._bt_on_message("BT:AA:BB", "while locked")
        check("a Bluetooth message arriving while locked is dropped, not stored readable",
              len(oc.load_messages("BT:AA:BB")) == n_before and b"while locked" not in all_bytes(Path(old)))
        app_core.identity.x25519_priv = saved
        alice.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
