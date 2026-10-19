"""
test_login.py - the web UI is behind a login.

  * opening the page is public; everything else needs a session
  * the passphrase is only accepted from this computer, never over the network
  * wrong passphrases are rate limited; sessions idle out / expire / can be dropped
  * first run (no identity yet) can create one, but only from this computer
  * LAN devices sign in with the access code instead of the passphrase
  * profiles on different ports don't clobber each other's login

Run:  python3 test/test_login.py
"""
import _testenv  # noqa: F401
import sys
from unittest import mock

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")

PW = "correct horse battery"
LAN = {"REMOTE_ADDR": "192.168.1.50"}


class FakeNode:
    def __init__(self):
        self.on_inbound_callbacks, self.on_peer_found_callbacks, self.on_contact_request_callbacks = [], [], []


def main():
    import enclave_messenger.main as app_core
    from enclave_messenger import web

    def hdr():
        return {"X-Enclave-CSRF": web._CSRF_TOKEN}

    def fake_start(passphrase=None, **kw):
        app_core.identity.load_identity(passphrase=passphrase)
        app_core._node = FakeNode()

    clock = [1_000_000.0]
    patches = [mock.patch.object(web, "_AUTH_ENABLED", True),
               mock.patch.object(web, "_now", lambda: clock[0]),
               mock.patch.object(app_core, "start_node", fake_start)]
    for p in patches: p.start()
    web._callbacks_registered = False
    app_core._node = None

    try:
        c = web.app.test_client()

        print("\n[the gate]")
        r = c.get("/")
        check("the page itself is public", r.status_code == 200 and b"Enclave Messenger" in r.data)
        check("...and is never cached", "no-store" in r.headers.get("Cache-Control", ""))
        check("/api/health is public", c.get("/api/health").status_code == 200)
        st = c.get("/api/auth/status").get_json()
        check("status is public and says not signed in", st["authenticated"] is False and st["login_required"] is True)
        for path in ("/api/peers", "/api/identity", "/api/identity/status", "/api/identity/share.svg",
                     "/api/plugins", "/api/chats", "/api/profiles", "/api/lan/status", "/ws"):
            r = c.get(path)
            check(f"{path} needs a login", r.status_code == 401 and r.get_json().get("login") is True)
        check("a POST also needs a login", c.post("/api/message/send", json={}, headers=hdr()).status_code == 401)

        print("\n[first run: no identity yet]")
        check("no identity on disk yet", not app_core.identity.has_identity())
        r = c.post("/api/identity/generate", json={"passphrase": PW}, headers=hdr(), environ_base=LAN)
        check("another device cannot create the identity", r.status_code == 401)
        check("...and nothing was created", not app_core.identity.has_identity())
        r = c.post("/api/node/start", json={"passphrase": PW}, headers=hdr())
        check("logging in before an identity exists is refused politely", r.status_code == 400)
        r = c.post("/api/identity/generate", json={"passphrase": PW}, headers=hdr())
        check("this computer can create it", r.status_code == 200 and app_core.identity.has_identity())
        check("...and whoever created it is signed in straight away",
              "enclave_session=" in r.headers.get("Set-Cookie", "") and c.get("/api/peers").status_code == 200)
        stranger = web.app.test_client()
        r = stranger.post("/api/identity/generate", json={"passphrase": "attacker pass"}, headers=hdr())
        check("once an identity exists the same call needs a login (cannot be overwritten)", r.status_code == 401)
        r = stranger.post("/api/identity/restore", json={"backup": {}, "passphrase": "x"}, headers=hdr())
        check("restore is also login-only once an identity exists", r.status_code == 401)
        c.post("/api/auth/logout", json={}, headers=hdr())         # continue as a signed-out browser

        print("\n[passphrase checks]")
        before = app_core.identity.get_user_id()
        check("verify_passphrase accepts the right one and rejects others",
              app_core.identity.verify_passphrase(PW) and not app_core.identity.verify_passphrase("nope")
              and not app_core.identity.verify_passphrase(""))
        check("...without changing the loaded identity", app_core.identity.get_user_id() == before)
        r = c.post("/api/auth/login", json={"passphrase": "wrong"}, headers=hdr())
        check("a wrong passphrase is rejected with no cookie",
              r.status_code == 403 and "enclave_session" not in r.headers.get("Set-Cookie", ""))
        r = c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr(), environ_base=LAN)
        check("the CORRECT passphrase is refused when it comes from another device",
              r.status_code == 403 and "never accepted" in r.get_json()["error"])
        check("...and the refusal leaks nothing about the passphrase", PW not in r.get_data(as_text=True))
        for _ in range(4):
            c.post("/api/auth/login", json={"passphrase": "wrong"}, headers=hdr())
        r = c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
        check("after 5 wrong tries even the right passphrase is locked out (429)", r.status_code == 429)
        web._LOGIN_FAILS.clear()

        print("\n[signing in]")
        r = c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
        cookie = r.headers.get("Set-Cookie", "")
        check("the right passphrase signs in and starts the node",
              r.status_code == 200 and r.get_json()["ok"] and app_core.get_node() is not None)
        check("session cookie is HttpOnly + SameSite=Strict",
              "enclave_session=" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie)
        check("it is a browser-session cookie (no Expires/Max-Age)", "Expires" not in cookie and "Max-Age" not in cookie)
        check("API calls now work", c.get("/api/peers").status_code == 200 and c.get("/api/identity").status_code == 200)
        check("status now says signed in", c.get("/api/auth/status").get_json()["authenticated"] is True)
        c2 = web.app.test_client()
        check("a different browser (no cookie) is still locked out", c2.get("/api/peers").status_code == 401)
        r = c.post("/api/node/start", json={"passphrase": "wrong"}, headers=hdr())
        check("/api/node/start (the old unlock call) is the same check", r.status_code == 403)
        web._LOGIN_FAILS.clear()

        print("\n[expiry]")
        clock[0] += 14 * 60
        check("still signed in after 14 idle minutes (and that use refreshes it)", c.get("/api/peers").status_code == 200)
        clock[0] += 14 * 60
        check("...refreshed again", c.get("/api/peers").status_code == 200)
        clock[0] += 16 * 60
        check("signed out after 16 idle minutes", c.get("/api/peers").status_code == 401)
        r = c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
        app_core.config.set_setting("session_idle_minutes", 0)
        clock[0] += 5 * 3600
        check("with idle expiry off a session survives hours of silence", c.get("/api/peers").status_code == 200)
        clock[0] += 8 * 3600
        check("...but never more than 12 hours in total", c.get("/api/peers").status_code == 401)
        app_core.config.set_setting("session_idle_minutes", 15)

        print("\n[logging out / asking every time]")
        c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
        r = c.post("/api/auth/logout", json={}, headers=hdr())
        check("logout answers and clears the cookie", r.status_code == 200 and "enclave_session=;" in r.headers.get("Set-Cookie", ""))
        check("...and the session is really gone server-side", c.get("/api/peers").status_code == 401)
        check("status still says an identity exists", c.get("/api/auth/status").get_json()["has_identity"] is True)
        c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
        app_core.config.set_setting("lock_on_page_load", True)
        check("with lock_on_page_load, fetching the page signs you out", c.get("/").status_code == 200
              and c.get("/api/peers").status_code == 401)
        app_core.config.set_setting("lock_on_page_load", False)

        print("\n[profiles on different ports]")
        with mock.patch.object(web, "_PORT", 5001):
            r = c.post("/api/auth/login", json={"passphrase": PW}, headers=hdr())
            check("the cookie name carries the port", "enclave_session_5001=" in r.headers.get("Set-Cookie", ""))
            check("that login works on its own port", c.get("/api/peers").status_code == 200)
        with mock.patch.object(web, "_PORT", 5002):
            check("...and does not sign you into the profile on another port", c.get("/api/peers").status_code == 401)

        print("\n[LAN devices]")
        web._enable_lan_mode()
        lan = web.app.test_client()
        r = lan.get("/api/peers", environ_base=LAN)
        check("a LAN device without the access code is stopped at the gate", r.status_code == 401)
        r = lan.post("/lan-login", data={"code": web._LAN_CODE}, environ_base=LAN)
        names = " ".join(r.headers.getlist("Set-Cookie"))
        check("the access code signs a LAN device in (LAN cookie + session cookie)",
              r.status_code == 302 and "enclave_lan=" in names and "enclave_session=" in names)
        check("...so it can use the app without ever typing the passphrase",
              lan.get("/api/peers", environ_base=LAN).status_code == 200)
        r = lan.post("/api/auth/login", json={"passphrase": PW}, headers=hdr(), environ_base=LAN)
        check("...and it still cannot send a passphrase over the network", r.status_code == 403)
        check("the host computer is not asked for the access code", c.get("/api/health").status_code == 200)
        web._LAN_MODE = False

        print("\n[switching it off]")
        with mock.patch.object(web, "_AUTH_ENABLED", False):
            check("ENCLAVE_NO_LOGIN-style mode leaves the API open (tests / throw-away dev runs only)",
                  web.app.test_client().get("/api/peers").status_code == 200
                  and web.app.test_client().get("/api/auth/status").get_json()["authenticated"] is True)
    finally:
        for p in patches: p.stop()
        app_core._node = None
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
