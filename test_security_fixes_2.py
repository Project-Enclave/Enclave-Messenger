"""
test_security_fixes_2.py — regression tests for the second round of fixes:

  1. passphrase must not travel in the URL
  2. --host lan requires an access code from non-loopback clients
  3. outbound peer addresses are validated (SSRF hardening) and
     redirects are refused
  4. user plugins are never imported until explicitly trusted (hash-pinned)

Run:  python3 test_security_fixes_2.py
"""
import _testenv  # noqa: F401  (src/ on sys.path + throw-away ENCLAVE_HOME)
import json, os, sys, tempfile, textwrap
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")

def main():
    # ---------------- 3. peer-address validation ----------------
    print("\n[peer address validation]")
    from enclave_messenger.core.network.transport import validate_peer_address as ok
    check("normal LAN address allowed",            ok("http://192.168.1.20:5001"))
    check("loopback allowed (local multi-node)",   ok("http://127.0.0.1:5001"))
    check("cloud metadata IP blocked",             not ok("http://169.254.169.254:80"))
    check("IPv4-mapped metadata IP blocked",       not ok("http://[::ffff:169.254.169.254]:80"))
    check("0.0.0.0 blocked",                       not ok("http://0.0.0.0:5001"))
    check("multicast blocked",                     not ok("http://224.0.0.1:5001"))
    check("file:// blocked",                       not ok("file:///etc/passwd"))
    check("ftp:// blocked",                        not ok("ftp://1.2.3.4:21"))
    check("path smuggling blocked",                not ok("http://1.2.3.4:80/admin"))
    check("query smuggling blocked",               not ok("http://1.2.3.4:80?x=1"))
    check("userinfo blocked",                      not ok("http://user:pw@1.2.3.4:80"))
    check("missing port blocked",                  not ok("http://1.2.3.4"))
    check("garbage blocked",                       not ok("not a url") and not ok(None))

    import enclave_messenger.core.network.transport as t
    from urllib.error import HTTPError
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    hits = []
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/health":
                self.send_response(302); self.send_header("Location", "/secret"); self.end_headers()
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        t._open(t.Request(f"http://127.0.0.1:{port}/health"), 3)
        followed = True
    except Exception:
        followed = False
    srv.shutdown()
    check("HTTP redirects are NOT followed", "/secret" not in hits)

    # ---------------- 2. LAN gate + 1. passphrase header ----------------
    print("\n[web: LAN access gate]")
    from enclave_messenger import web
    web._enable_lan_mode()
    code = web._LAN_CODE
    check("access code looks like XXXX-XXXX", len(code) == 9 and code[4] == "-")
    lan = {"REMOTE_ADDR": "192.168.1.50"}
    with web.app.test_client() as c:
        r = c.get("/", environ_base=lan)
        check("LAN client without code gets the login page", r.status_code == 401 and b"access code" in r.data)
        r = c.get("/api/chats", environ_base=lan)
        check("LAN client API call without code -> 401", r.status_code == 401)
        r = c.post("/lan-login", data={"code": "WRONG-CODE"}, environ_base=lan)
        check("wrong code rejected", r.status_code == 401)
        for _ in range(6):
            r = c.post("/lan-login", data={"code": "WRONG-CODE"}, environ_base=lan)
        check("repeated wrong codes are rate-limited (429)", r.status_code == 429)
    web._LAN_FAILS.clear()
    with web.app.test_client() as c:
        r = c.post("/lan-login", data={"code": code.lower()}, environ_base=lan)
        check("correct code accepted (case-insensitive) and sets cookie",
              r.status_code == 302 and "enclave_lan" in r.headers.get("Set-Cookie", ""))
        check("session cookie is HttpOnly + SameSite=Strict",
              "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Strict" in r.headers["Set-Cookie"])
        r = c.get("/api/chats", environ_base=lan)
        check("after login the LAN client can use the API", r.status_code != 401)
    with web.app.test_client() as c:
        r = c.get("/api/chats")   # default REMOTE_ADDR is 127.0.0.1
        check("loopback client is never asked for the code", r.status_code != 401)
    web._LAN_MODE = False

    print("\n[web: passphrase must not be in the URL]")
    with web.app.test_client() as c:
        r = c.get("/api/messages/someone?passphrase=hunter2")
        check("?passphrase= is refused with 400", r.status_code == 400)
        check("error does not echo the secret", b"hunter2" not in r.data)

    # ---------------- 4. plugin trust ----------------
    print("\n[plugins: untrusted code is never imported]")
    from enclave_messenger.core.plugins import manager as pm
    tmp = tempfile.mkdtemp()
    marker = os.path.join(tmp, "PWNED")
    pdir = os.path.join(tmp, "evil")
    os.makedirs(pdir)
    json.dump({"id": "evil", "display_name": "Evil", "version": "1", "description": "x",
               "author": "x", "permissions": []}, open(os.path.join(pdir, "manifest.json"), "w"))
    src = textwrap.dedent(f'''
        from enclave_messenger.core.plugins.manager import EnclavePlugin
        open({marker!r}, "w").write("top-level code ran")
        class Plugin(EnclavePlugin):
            def enable(self, core): pass
            def disable(self): pass
            def get_settings_schema(self): return {{}}
            def configure(self, s): pass
            def get_status(self): return {{"ok": True}}
    ''')
    open(os.path.join(pdir, "main.py"), "w").write(src)

    class Cfg:
        def __init__(s): s.d = {}
        def get(s, k, default=None): return s.d.get(k, default)
        def set(s, k, v): s.d[k] = v
        def get_setting(s, k, default=None): return default
    class Log:
        def __getattr__(s, n): return lambda *a, **k: None
    pm.USER_PLUGIN_DIR = tmp
    cfg = Cfg()
    mgr = pm.PluginManager(cfg, None, None, None, Log())
    mgr._scan_dir(tmp, builtin=False)
    check("untrusted plugin top-level code did NOT run on discovery", not os.path.exists(marker))
    r = mgr.enable("evil")
    check("enable() on untrusted plugin refused with needs_trust",
          r.get("ok") is False and r.get("needs_trust") is True)
    check("untrusted plugin is listed but flagged untrusted",
          any(p["id"] == "evil" and p["trusted"] is False for p in mgr.get_all()))
    r = mgr.trust("evil")
    check("explicit trust loads the plugin", r.get("ok") is True and os.path.exists(marker))
    os.remove(marker)
    # tampering after trust: new manager, changed file -> trust revoked
    open(os.path.join(pdir, "main.py"), "a").write("\n# tampered\n")
    mgr2 = pm.PluginManager(cfg, None, None, None, Log())
    mgr2._scan_dir(tmp, builtin=False)
    check("modifying main.py revokes trust (hash pinned) and code is not run",
          not os.path.exists(marker) and mgr2.enable("evil").get("needs_trust") is True)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
