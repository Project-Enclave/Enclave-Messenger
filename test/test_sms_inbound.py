"""
test_sms_inbound.py - receiving (and answering) SMS through the android-sms-gateway app.

  * signature rules: HMAC-SHA256 over raw body + timestamp, +-5 minutes, constant time
  * the webhook refuses everything it cannot verify, and nothing readable reaches the disk
  * it works with the login gate and LAN mode ON (the phone has no cookie/code/CSRF header)
  * re-delivered webhooks are not stored twice; a locked identity answers 503 (gateway retries)
  * phone-number chats send by SMS, record the outcome, and can be retried

Run:  python3 test/test_sms_inbound.py
"""
import _testenv  # noqa: F401
import hashlib, hmac, json, sys, time
from pathlib import Path
from unittest import mock

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")

KEY = "signing-key-from-the-phone-app"


def sign(raw: bytes, ts, key=KEY):
    return hmac.new(key.encode(), raw + str(ts).encode(), hashlib.sha256).hexdigest()


def event(message="hello from a friend", sender="+6505551212", mid="m-1", kind="sms:received"):
    return json.dumps({"deviceId": "d", "event": kind, "id": "evt-" + mid, "webhookId": "w",
                       "payload": {"messageId": mid, "message": message, "sender": sender, "recipient": "+1",
                                   "simNumber": 1, "receivedAt": "2026-10-11T15:16:06.000+05:30"}}).encode()


def main():
    from enclave_messenger.core import sms_inbound as si
    import enclave_messenger.main as app_core
    from enclave_messenger import web
    from enclave_messenger.core.crypto.e2e import E2EManager

    print("\n[signature + parsing]")
    now = 1_800_000_000
    raw = event()
    good = sign(raw, now)
    check("a correct signature verifies", si.verify_signature(KEY, raw, str(now), good, now=now))
    check("signature hex case does not matter", si.verify_signature(KEY, raw, str(now), good.upper(), now=now))
    check("wrong key is rejected", not si.verify_signature("other", raw, str(now), good, now=now))
    check("a tampered body is rejected", not si.verify_signature(KEY, raw + b" ", str(now), good, now=now))
    check("a different timestamp (signature reused) is rejected", not si.verify_signature(KEY, raw, str(now + 1), good, now=now))
    check("4 minutes of clock skew is fine", si.verify_signature(KEY, raw, str(now - 240), sign(raw, now - 240), now=now))
    check("a request captured 6 minutes ago cannot be replayed", not si.verify_signature(KEY, raw, str(now - 360), sign(raw, now - 360), now=now))
    check("a timestamp from the future is rejected too", not si.verify_signature(KEY, raw, str(now + 400), sign(raw, now + 400), now=now))
    check("no key / no header / junk timestamp are rejected",
          not si.verify_signature("", raw, str(now), good, now=now) and not si.verify_signature(KEY, raw, "", good, now=now)
          and not si.verify_signature(KEY, raw, str(now), "", now=now) and not si.verify_signature(KEY, raw, "abc", good, now=now))
    p = si.parse_received(event())
    check("a received-SMS event is parsed", p["sender"] == "+6505551212" and p["message"] == "hello from a friend" and p["ext_id"] == "m-1")
    check("other event types are ignorable, not errors", si.parse_received(event(kind="sms:sent")) is None)
    for bad in (b"not json", b"[]", b'{"event":"sms:received"}', b'{"event":"sms:received","payload":{"message":"x"}}',
                b'{"event":"sms:received","payload":{"sender":"+1555","message":""}}'):
        try:
            si.parse_received(bad); ok = False
        except ValueError:
            ok = True
        if not ok: break
    check("malformed events are rejected", ok)
    check("an old-style payload (phoneNumber) is understood too",
          si.parse_received(b'{"event":"sms:received","payload":{"message":"x","phoneNumber":"+15551234567"}}')["sender"] == "+15551234567")
    check("sender -> chat id: numbers are cleaned, names get a prefix",
          si.sender_chat_id("+1 (650) 555-1212") == "+16505551212" and si.sender_chat_id("6505551212") == "6505551212"
          and si.sender_chat_id("MyBank") == "sms:MyBank" and si.sender_chat_id("12345") == "sms:12345")
    try:
        si.sender_chat_id("<script>"); bad = False
    except ValueError:
        bad = True
    check("a sender with odd characters is refused", bad)

    print("\n[the webhook, with the login gate and LAN mode switched ON]")
    app_core.identity.generate_new_identity()
    app_core.identity.save_identity(passphrase="pw")
    patches = [mock.patch.object(web, "_AUTH_ENABLED", True)]
    for p_ in patches: p_.start()
    web._enable_lan_mode()
    pushed = []
    real_bc = web._ws_broadcast
    web._ws_broadcast = lambda ev, data: pushed.append((ev, data))
    chats = app_core.chats
    phone = {"REMOTE_ADDR": "192.168.1.77"}                       # the phone, on the LAN, with no cookie

    def post(body, ts=None, sig=None, key=KEY, env=phone, headers=None):
        ts = int(time.time()) if ts is None else ts
        h = {"X-Timestamp": str(ts), "X-Signature": sig if sig is not None else sign(body, ts, key),
             "Content-Type": "application/json"}
        h.update(headers or {})
        return web.app.test_client().post("/api/sms/webhook", data=body, headers=h, environ_base=env)
    try:
        app_core.config.set_setting("sms_signing_key", "")
        r = post(event())
        check("no signing key configured: everything is refused (503)", r.status_code == 503 and not chats.list_chats())
        app_core.config.set_setting("sms_signing_key", KEY)

        check("other API paths are still locked for that same phone", web.app.test_client().get("/api/peers", environ_base=phone).status_code == 401)
        r = post(event(), sig="0" * 64)
        check("a wrong signature is refused (401) and stores nothing", r.status_code == 401 and not chats.list_chats())
        r = post(event(), ts=int(time.time()) - 600)
        check("a stale request is refused (401)", r.status_code == 401 and not chats.list_chats())
        r = post(event(), key="someone elses key")
        check("a request signed with another key is refused", r.status_code == 401)
        r = web.app.test_client().post("/api/sms/webhook", data=event(), environ_base=phone)
        check("a request with no signature headers is refused", r.status_code == 401)
        big = b'{"event":"sms:received","payload":{"sender":"+16505551212","message":"' + b"x" * 70000 + b'"}}'
        check("an oversized body is refused (413) before parsing", post(big).status_code == 413)

        r = post(event())
        check("a valid, signed text is accepted", r.status_code == 200 and r.get_json()["status"] == "stored")
        cid = "+6505551212"
        recs = chats.load_messages(cid)
        check("it is stored in the sender's phone-number chat", len(recs) == 1 and recs[0]["sender"] == "peer")
        check("...sealed to our key: the text is not readable in the stored record", "hello from a friend" not in recs[0]["token"]
              and E2EManager.is_e2e_token(recs[0]["token"]))
        data_dir = Path(chats.chats_dir)
        check("...and appears nowhere in the chat files on disk",
              b"hello from a friend" not in b"".join(f.read_bytes() for f in data_dir.rglob("*") if f.is_file()))
        shown = app_core.get_messages_decrypted(cid, "")
        check("it displays normally once decrypted", len(shown) == 1 and shown[0]["text"] == "hello from a friend")
        check("the received time of the phone is kept (UTC)", recs[0]["ts"].startswith("2026-10-11T09:46:06"))
        check("the open page is told about it", pushed and pushed[-1][0] == "new_message" and pushed[-1][1]["chat_id"] == cid)

        r = post(event())
        check("the same webhook delivered again is not stored twice", r.get_json()["status"] == "duplicate"
              and len(chats.load_messages(cid)) == 1)
        r = post(event(message="second text", mid="m-2"))
        check("a different message id is stored", r.get_json()["status"] == "stored" and len(chats.load_messages(cid)) == 2)
        r = post(event(kind="sms:sent", mid="m-3"))
        check("other event types are acknowledged and ignored", r.status_code == 200 and r.get_json()["status"] == "ignored")
        r = post(event(sender="MyBank", message="your code is 1234", mid="m-4"))
        check("a named sender gets a readable, non-replyable chat", r.get_json()["status"] == "stored" and chats.load_messages("sms:MyBank"))
        r = post(event(sender="<script>alert(1)</script>", mid="m-5"))
        check("an unusable sender is ignored, not stored", r.status_code == 200 and r.get_json()["status"] == "ignored")
        r = post(b"{not json", sig=None)
        check("a signed but malformed body is a 400", r.status_code == 400)

        saved = app_core.identity.x25519_priv
        app_core.identity.x25519_priv = None
        n_before = len(chats.list_chats())
        r = post(event(message="while locked", mid="m-6"))
        check("while the identity is locked it answers 503 so the gateway retries later",
              r.status_code == 503 and len(chats.list_chats()) == n_before)
        app_core.identity.x25519_priv = saved
        r = post(event(message="while locked", mid="m-6"))
        check("...and the retry succeeds once unlocked", r.get_json()["status"] == "stored")
    finally:
        web._ws_broadcast = real_bc
        web._LAN_MODE = False
        for p_ in patches: p_.stop()

    print("\n[settings routes need a login; the webhook route does not]")
    with mock.patch.object(web, "_AUTH_ENABLED", True):
        c = web.app.test_client()
        hdr = {"X-Enclave-CSRF": web._CSRF_TOKEN}
        check("reading the SMS settings needs a login", c.get("/api/sms/inbound").status_code == 401)
        check("saving a signing key needs a login", c.post("/api/sms/inbound", json={"signing_key": "x" * 12}, headers=hdr).status_code == 401)
        check("registering a webhook needs a login", c.post("/api/sms/inbound/register", json={"url": "http://127.0.0.1:5000/api/sms/webhook"}, headers=hdr).status_code == 401)
    c = web.app.test_client(); hdr = {"X-Enclave-CSRF": web._CSRF_TOKEN}
    check("a too-short signing key is refused", c.post("/api/sms/inbound", json={"signing_key": "abc"}, headers=hdr).status_code == 400)
    r = c.post("/api/sms/inbound", json={"signing_key": "a-good-signing-key"}, headers=hdr)
    check("a good key is saved and reported as configured", r.status_code == 200 and r.get_json()["configured"] is True
          and app_core.config.get_setting("sms_signing_key") == "a-good-signing-key")
    app_core.config.set_setting("sms_signing_key", KEY)
    st = c.get("/api/sms/inbound").get_json()
    check("status shows what arrived since start", st["configured"] and st["received_count"] >= 3 and st["webhook_path"] == "/api/sms/webhook")
    for bad_url in ("ftp://127.0.0.1/api/sms/webhook", "http://u:p@127.0.0.1:5000/api/sms/webhook", "http://127.0.0.1:5000/other", "nonsense"):
        check(f"registering {bad_url!r} is refused", c.post("/api/sms/inbound/register", json={"url": bad_url}, headers=hdr).status_code == 400)
    with mock.patch.object(app_core, "register_sms_webhook", return_value={"id": "x"}) as reg:
        r = c.post("/api/sms/inbound/register", json={"url": "http://127.0.0.1:5000/api/sms/webhook"}, headers=hdr)
        check("a valid address is registered with the gateway as an sms:received webhook",
              r.status_code == 200 and reg.call_args[0][0] == "http://127.0.0.1:5000/api/sms/webhook")
    with mock.patch.object(app_core, "register_sms_webhook", side_effect=RuntimeError("401 unauthorized")):
        r = c.post("/api/sms/inbound/register", json={"url": "http://127.0.0.1:5000/api/sms/webhook"}, headers=hdr)
        check("a gateway error is reported, not swallowed", r.status_code == 502 and "401" in r.get_json()["error"])
    app_core.config.set_setting("sms_signing_key", "")
    check("registering without a saved key is refused (every text would bounce)",
          c.post("/api/sms/inbound/register", json={"url": "http://127.0.0.1:5000/api/sms/webhook"}, headers=hdr).status_code == 400)

    print("\n[answering by SMS from a phone-number chat]")
    to = "+16505559999"
    with mock.patch.object(app_core, "send_sms", return_value={"id": "g1"}) as snd:
        ok = app_core.send_message(to, "on my way, SECRET-SMS-MARKER")
        recs = chats.load_messages(to)
        check("the text is handed to the gateway", ok is True and snd.call_args[0] == (to, "on my way, SECRET-SMS-MARKER"))
        check("our copy is sealed, marked queued, via sms", len(recs) == 1 and recs[0]["status"] == "queued" and recs[0]["via"] == "sms"
              and "SECRET-SMS-MARKER" not in recs[0]["token"])
        check("...and shows normally", app_core.get_messages_decrypted(to, "")[0]["text"] == "on my way, SECRET-SMS-MARKER")
    with mock.patch.object(app_core, "send_sms", side_effect=RuntimeError("gateway down")):
        ok = app_core.send_message(to, "second")
        failed = [m for m in chats.load_messages(to) if m.get("status") == "failed"]
        check("a gateway failure is recorded as failed (not lost)", ok is False and len(failed) == 1)
    with mock.patch.object(app_core, "send_sms", return_value={}) as snd:
        check("retry re-sends the decrypted text and flips the same record to queued",
              app_core.retry_message(to, failed[0]["ts"]) is True and snd.call_args[0] == (to, "second")
              and [m["status"] for m in chats.load_messages(to)] == ["queued", "queued"])
        check("retry of a message that is not failed does nothing", app_core.retry_message(to, failed[0]["ts"]) is False)
    saved = app_core.identity.x25519_priv
    app_core.identity.x25519_priv = None
    with mock.patch.object(app_core, "send_sms") as snd:
        try:
            app_core.send_message(to, "locked"); refused = False
        except RuntimeError:
            refused = True
        check("a locked identity refuses to send, and nothing leaves the computer", refused and not snd.called)
    app_core.identity.x25519_priv = saved
    check("a node-id / ip chat is unaffected by the SMS branch", not app_core.is_phone_chat_id("EWyfLZRjNytwrEn3JrCr5Sz7v6X3NAghYbNZZ6Njsq8")
          and not app_core.is_phone_chat_id("192.168.1.5:43100") and app_core.is_phone_chat_id("+16505551212"))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
