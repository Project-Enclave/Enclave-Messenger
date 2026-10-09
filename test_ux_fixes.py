"""
test_ux_fixes.py - tests for delivery status/retry, identity backup+restore,
share/QR, plugin routes (secrets hidden), LAN status, and the scanner port.

Run:  python3 test_ux_fixes.py
"""
import _testenv  # noqa: F401  (src/ on sys.path + throw-away ENCLAVE_HOME)
import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")

def main():
    # ---- chat_store: status fields + in-place update ----
    print("\n[chat store: delivery status]")
    from enclave_messenger.core.storage.chat_store import ChatStore
    cs = ChatStore(tempfile.mkdtemp())
    cs.append_message("peer", {"token": "hi", "plaintext": True, "sender": "me", "ts": "T1",
                               "status": "failed", "via": ""})
    cs.append_message("peer", {"token": "yo", "sender": "peer", "ts": "T2"})
    old = cs.load_messages("peer")
    check("inbound records carry no status key", "status" not in old[1])
    check("update_message flips failed -> delivered",
          cs.update_message("peer", "T1", status="delivered", via="direct"))
    m = cs.load_messages("peer")
    check("status persisted without duplicating the message",
          len(m) == 2 and m[0]["status"] == "delivered" and m[0]["via"] == "direct")
    check("update_message cannot rewrite the text",
          not cs.update_message("peer", "T1", token="EVIL") and cs.load_messages("peer")[0]["token"] == "hi")
    check("update_message ignores inbound messages",
          not cs.update_message("peer", "T2", status="delivered"))

    # ---- router: via / status / retry against a real in-process node pair ----
    print("\n[router: delivered / failed / retry]")
    from enclave_messenger import main as app_core
    from enclave_messenger.core.network.router import Node
    check("router reports direct vs relay vs failed",
          Node._status_for("direct") == "delivered" and Node._status_for("relay") == "relayed"
          and Node._status_for(None) == "failed")

    # real two-node scenario: bob offline -> failed + retry -> delivered
    import time, shutil
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_security_fixes import make_node
    tmp = tempfile.mkdtemp(prefix="enclave_ux_")
    try:
        alice, ap, ac = make_node(tmp, "alice", 53101)
        bob,   bp, bc = make_node(tmp, "bob",   53102)
        alice.start()          # bob deliberately NOT started yet
        time.sleep(0.3)
        bid = bob._identity["user_id"]
        ap.upsert(user_id=bid, username="bob", ed25519_pub=bob._identity["ed25519_pub"],
                  x25519_pub=bob._identity["x25519_pub"], ip="127.0.0.1", port=53102)
        bp.upsert(user_id=alice._identity["user_id"], username="alice",
                  ed25519_pub=alice._identity["ed25519_pub"],
                  x25519_pub=alice._identity["x25519_pub"], ip="127.0.0.1", port=53101)

        ok = alice.send(bid, "are you there?")
        rec = ac.load_messages(bid)
        check("offline peer: send() reports failure", ok is False)
        check("offline peer: bubble is kept and marked failed",
              len(rec) == 1 and rec[0]["status"] == "failed" and rec[0]["token"] == "are you there?")
        ts = rec[0]["ts"]

        check("retry while still offline stays failed, no duplicate bubble",
              alice.retry_message(bid, ts) is False and len(ac.load_messages(bid)) == 1
              and ac.load_messages(bid)[0]["status"] == "failed")

        bob.start(); time.sleep(0.4)
        check("retry after peer comes online succeeds", alice.retry_message(bid, ts) is True)
        rec = ac.load_messages(bid)
        check("same bubble flipped to delivered/direct (no duplicate)",
              len(rec) == 1 and rec[0]["status"] == "delivered" and rec[0]["via"] == "direct")
        time.sleep(0.3)
        got = bc.load_messages(alice._identity["user_id"])
        check("bob received exactly one copy", len(got) == 1)
        check("retry of an already-delivered message is refused", alice.retry_message(bid, ts) is False)

        ok2 = alice.send(bid, "second")
        r2 = [m for m in ac.load_messages(bid) if m["token"] == "second"][0]
        check("normal send to online peer is marked delivered/direct",
              ok2 and r2["status"] == "delivered" and r2["via"] == "direct")

        ok3 = alice.send("nobody-knows-this-id", "lost?")
        r3 = ac.load_messages("nobody-knows-this-id")
        check("unknown peer: typed text is kept as a failed bubble, not lost",
              ok3 is False and len(r3) == 1 and r3[0]["status"] == "failed")
        alice.stop(); bob.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- web routes ----
    print("\n[web: share / backup / restore / plugins / lan]")
    from enclave_messenger import web
    web._LAN_MODE = False
    with web.app.test_client() as c:
        r = c.get("/api/lan/status")
        check("lan status reports off by default", r.get_json() == {"lan_mode": False})

        r = c.get("/api/identity/share")
        check("share endpoint answers", r.status_code == 200 and "node_id" in r.get_json())

        r = c.get("/api/plugins")
        d = r.get_json()
        check("plugin list works", r.status_code == 200 and isinstance(d.get("plugins"), list))
        sms = next((p for p in d["plugins"] if p["id"] == "sms_gateway"), None)
        check("sms_gateway plugin listed", sms is not None)

    # secrets must be blanked
    info = web._public_plugin_info({
        "schema": [{"key": "password", "type": "password"}, {"key": "host", "type": "text"}],
        "settings": {"password": "hunter2", "host": "cloud"}})
    check("plugin password setting is never sent to the browser",
          info["settings"]["password"] == "" and info["settings"]["host"] == "cloud")

    # LAN status reveals the code only to loopback
    web._enable_lan_mode()
    with web.app.test_client() as c:
        r = c.get("/api/lan/status")
        check("loopback sees the access code", r.get_json().get("code") == web._LAN_CODE)
        r = c.post("/lan-login", data={"code": web._LAN_CODE}, environ_base={"REMOTE_ADDR": "10.0.0.9"})
        cookie = r.headers["Set-Cookie"].split(";")[0]
    with web.app.test_client() as c:
        c.set_cookie("enclave_lan", cookie.split("=", 1)[1], domain="localhost")
        r = c.get("/api/lan/status", environ_base={"REMOTE_ADDR": "10.0.0.9"})
        check("a signed-in LAN client does NOT get the code", "code" not in r.get_json())
    web._LAN_MODE = False

    # ---- identity backup / restore round trip ----
    print("\n[identity backup + restore]")
    from enclave_messenger.core.identity.key_manager import IdentityManager
    d1 = tempfile.mkdtemp(); d2 = tempfile.mkdtemp()
    orig = app_core.identity
    try:
        a = IdentityManager(storage_dir=d1)
        a.generate_new_identity(); a.save_identity(passphrase="correct horse")
        app_core.identity = a
        bundle = app_core.export_identity_backup()
        check("backup bundle has both keys and a version",
              bundle["enclave_identity_backup"] == 1 and "ENCRYPTED PRIVATE KEY" in bundle["ed25519_pem"])
        check("backup contains no plaintext private key",
              "BEGIN PRIVATE KEY" not in json.dumps(bundle))

        b = IdentityManager(storage_dir=d2)
        app_core.identity = b
        try:
            app_core.restore_identity_backup(bundle, "wrong pass"); bad = False
        except ValueError: bad = True
        check("wrong passphrase refused and nothing written", bad and not b.has_identity())
        try:
            app_core.restore_identity_backup({"x": 1}, "correct horse"); bad = False
        except ValueError: bad = True
        check("non-backup JSON refused", bad and not b.has_identity())
        evil = dict(bundle); evil["ed25519_pem"] = "-----BEGIN ENCRYPTED PRIVATE KEY-----" + "A" * 9000
        try:
            app_core.restore_identity_backup(evil, "correct horse"); bad = False
        except ValueError: bad = True
        check("oversized/garbage key refused", bad and not b.has_identity())

        res = app_core.restore_identity_backup(bundle, "correct horse")
        check("restore gives back the SAME user id", res["node_id"] == a.get_user_id())
        check("restored key files are mode 600",
              (os.stat(b.ed25519_file).st_mode & 0o777) == 0o600)
        try:
            app_core.restore_identity_backup(bundle, "correct horse"); bad = False
        except ValueError: bad = True
        check("restore refuses to overwrite an existing identity", bad)
    finally:
        app_core.identity = orig

    # ---- scanner default port ----
    print("\n[scanner]")
    from enclave_messenger.core.network.scanner import ENCLAVE_PORT
    from enclave_messenger.core.network.router import TRANSPORT_PORT
    check("scanner probes the real default transport port", ENCLAVE_PORT == TRANSPORT_PORT)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
