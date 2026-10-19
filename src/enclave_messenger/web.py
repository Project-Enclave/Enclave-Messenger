"""
web.py — Enclave Messenger browser UI.
Run with: python web.py [--host host|lan] [--port 5000] [--profile name]

  --host host     Bind to 127.0.0.1 only (default)
  --host lan      Bind to 0.0.0.0 (all interfaces)
  --port 5001     Override web UI port (default: 5000, or profile's web_port)
  --profile alice Switch to a named profile

To run two instances:
    python web.py --profile alice --port 5000
    python web.py --profile bob   --port 5001

Alternatively set ENCLAVE_HOST / ENCLAVE_PORT / ENCLAVE_PROFILE env vars.

This file only handles HTTP ↔ browser.
The actual logic for crypto and comms is NOT handled by this file.
"""

import argparse
import io
import os
import re
import secrets
import subprocess
import sys
import threading
import traceback
from datetime import datetime, timezone, timedelta

from urllib.parse import unquote

from flask import Flask, request, jsonify, render_template, abort, redirect, make_response
try:
    from flask_sock import Sock
    _SOCK_AVAILABLE = True
except ImportError:
    _SOCK_AVAILABLE = False

from enclave_messenger import main as app_core
from enclave_messenger.core import sms_inbound
from enclave_messenger.spawn import spawn_web_profile
from enclave_messenger.core import profiles as _profiles
from enclave_messenger.core.network.scanner import scan_lan_peers, ENCLAVE_PORT
from enclave_messenger.core.plugins.builtin.bluetooth.main import BluetoothUnavailableError

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------
# request.get_json(force=True) throughout this file parses the body as JSON
# regardless of the declared Content-Type header. That's convenient, but it
# means a malicious webpage open in ANY OTHER TAB can fetch() this API with
# Content-Type: text/plain — a "simple" content type per the Fetch spec —
# and the browser will send the request with ZERO CORS preflight, bypassing
# same-origin protections entirely. Concretely: with no defense here, any
# website could silently send messages as you, overwrite your SMS gateway
# credentials, or (via /api/identity/regenerate falling back to a "cached"
# passphrase) corrupt your live identity — all with no interaction beyond
# you having this app open in one tab while browsing.
#
# Fix: a random per-process token, embedded in the page at render time
# (same-origin only — a cross-origin page cannot read another origin's
# rendered HTML), required as a custom header on every mutating request.
# Custom headers always force a CORS preflight, and this server never sends
# Access-Control-Allow-Origin, so the browser refuses to send the real
# request cross-origin.
#
# That token is NOT authentication: anyone who can open the page gets it.
# Who may use the app is decided by the login session below.
_CSRF_TOKEN = secrets.token_urlsafe(32)
_CSRF_HEADER = "X-Enclave-CSRF"
# The phone's SMS gateway app POSTs incoming texts here. It cannot carry our CSRF header, a login
# cookie or the LAN access code, so this ONE path skips those gates. It is authenticated by the
# HMAC signature on every request instead (see core/sms_inbound.py), and refuses everything until a
# signing key has been configured.
_SMS_WEBHOOK = "/api/sms/webhook"
_CSRF_EXEMPT_PATHS = {"/api/health", _SMS_WEBHOOK}
_PASSPHRASE_HEADER = "X-Enclave-Passphrase"


@app.before_request
def _check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path in _CSRF_EXEMPT_PATHS:
            return
        if not request.path.startswith("/api/"):
            return
        token = request.headers.get(_CSRF_HEADER, "")
        if not secrets.compare_digest(token, _CSRF_TOKEN):
            abort(403, description="missing or invalid CSRF token")

# ---------------------------------------------------------------------------
# LAN-mode access gate
# ---------------------------------------------------------------------------
# The CSRF token above stops *other websites* from driving your browser at
# this API. It does nothing about another device on the network opening the
# page directly (the token is embedded in that page). So when bound to
# 0.0.0.0 (--host lan) every non-loopback client must first enter a one-time
# access code that is printed in the terminal of the machine running the
# app. Loopback clients (the person at the keyboard) are never asked.
_LAN_MODE = False
_LAN_CODE = None            # set at startup when --host lan is used
_LAN_COOKIE = "enclave_lan"
_LAN_SESSIONS: set = set()
_LAN_FAILS: dict = {}       # ip -> [timestamps of recent failed attempts]
_LAN_MAX_FAILS = 5
_LAN_FAIL_WINDOW = 300      # seconds
_LAN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I


def _new_lan_code() -> str:
    raw = "".join(secrets.choice(_LAN_ALPHABET) for _ in range(8))
    return raw[:4] + "-" + raw[4:]


def _enable_lan_mode() -> str:
    global _LAN_MODE, _LAN_CODE
    _LAN_MODE = True
    _LAN_CODE = _new_lan_code()
    return _LAN_CODE


def _is_loopback(addr: str) -> bool:
    return addr in ("127.0.0.1", "::1") or (addr or "").startswith("::ffff:127.")


_LAN_LOGIN_HTML = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Enclave Messenger - access code</title>
<body style="font-family:system-ui;max-width:22rem;margin:4rem auto;padding:0 1rem">
<h2>enclave messenger</h2>
<p>This instance is shared on the local network. Enter the access code shown
in the terminal of the computer running it.</p>
<p style="color:#b00">__ERR__</p>
<form method=post action=/lan-login>
<input name=code autofocus autocomplete=off placeholder="XXXX-XXXX"
 style="font-size:1.2rem;padding:.4rem;width:100%;box-sizing:border-box">
<button style="margin-top:.6rem;padding:.5rem 1rem">unlock</button>
</form>"""


def _lan_login_page(error: str = "", status: int = 401):
    resp = make_response(_LAN_LOGIN_HTML.replace("__ERR__", error), status)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.before_request
def _require_lan_auth():
    if not _LAN_MODE or _is_loopback(request.remote_addr):
        return
    if request.path in ("/lan-login", _SMS_WEBHOOK):
        return
    token = request.cookies.get(_LAN_COOKIE, "")
    if token and token in _LAN_SESSIONS:
        return
    if request.path.startswith("/api/") or request.path == "/ws":
        return jsonify({"error": "access code required"}), 401
    return _lan_login_page()


@app.route("/lan-login", methods=["GET", "POST"])
def lan_login():
    if not _LAN_MODE or _is_loopback(request.remote_addr):
        return redirect("/")
    if request.method == "GET":
        return _lan_login_page(status=200)

    ip = request.remote_addr or "?"
    now = datetime.now(timezone.utc).timestamp()
    recent = [t for t in _LAN_FAILS.get(ip, []) if now - t < _LAN_FAIL_WINDOW]
    if len(recent) >= _LAN_MAX_FAILS:
        _LAN_FAILS[ip] = recent
        return _lan_login_page("too many attempts, try again in a few minutes", 429)

    supplied = (request.form.get("code") or
                (request.get_json(silent=True) or {}).get("code") or "")
    supplied = supplied.strip().upper()
    if _LAN_CODE and secrets.compare_digest(supplied, _LAN_CODE):
        _LAN_FAILS.pop(ip, None)
        session = secrets.token_urlsafe(32)
        _LAN_SESSIONS.add(session)
        resp = redirect("/")
        resp.set_cookie(_LAN_COOKIE, session, httponly=True, samesite="Strict")
        return _issue_session(resp, "lan")

    recent.append(now)
    _LAN_FAILS[ip] = recent
    return _lan_login_page("wrong code", 401)


# ---------------------------------------------------------------------------
# WebSocket broker
# ---------------------------------------------------------------------------
import json as _json

if _SOCK_AVAILABLE:
    _sock = Sock(app)

_ws_clients: list = []
_ws_lock = threading.Lock()


def _ws_broadcast(event: str, data: dict):
    frame = _json.dumps({"event": event, **data})
    dead = []
    with _ws_lock:
        clients = list(_ws_clients)
    for ws in clients:
        try:
            ws.send(frame)
        except Exception:
            dead.append(ws)
    if dead:
        with _ws_lock:
            for ws in dead:
                try:
                    _ws_clients.remove(ws)
                except ValueError:
                    pass

# ---------------------------------------------------------------------------
# Peer staleness helper
# ---------------------------------------------------------------------------

_PEER_STALE_SECONDS = 40


def _stamp_online(peers: list) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_PEER_STALE_SECONDS)
    result = []
    for p in peers:
        peer = dict(p)
        last_seen_str = peer.get("last_seen", "")
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            peer["online"] = last_seen >= cutoff
        except (ValueError, TypeError):
            peer["online"] = False
        result.append(peer)
    return result


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def err(msg, code=500, exc=None):
    p = {"error": msg}
    # Stack traces are useful locally but are a straight-up recon gift to
    # anyone hitting this API over the LAN (--host lan). Only include them
    # when debug mode is explicitly on; always log the full trace server-side.
    if exc:
        tb = traceback.format_exc()
        log_line = f"[web] {msg}\n{tb}"
        try:
            app_core.log.warning(log_line)
        except Exception:
            print(log_line)
        if app_core.config.get_setting("debug", False):
            p["detail"] = tb
    return jsonify(p), code

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Login sessions
# ---------------------------------------------------------------------------
# Opening the page is public; everything else needs a session.
#
#   * The passphrase is only ever accepted from THIS computer (loopback). Typing
#     it from another device would send it across the network in clear text, so
#     LAN devices sign in with the one-time access code instead (see above).
#   * A session is a random cookie (HttpOnly, SameSite=Strict, dies with the
#     browser). It expires after `session_idle_minutes` of silence (default 15,
#     0 = never) and after 12 hours in any case. The page also locks itself when
#     you stop touching it, and has a lock button.
#   * Setting `lock_on_page_load` makes every fetch of the page sign you out, so
#     the passphrase is asked every time.
#   * Wrong passphrases are rate-limited (5 per 5 minutes) because checking one
#     is the expensive key derivation an attacker would want to repeat.
#   * ENCLAVE_NO_LOGIN=1 turns the gate off. Meant for tests and throw-away dev
#     runs, never for real data.
import time as _time

_AUTH_ENABLED = os.environ.get("ENCLAVE_NO_LOGIN", "").strip().lower() not in ("1", "true", "yes")
_PORT = None                      # set at startup; keeps cookies of different ports apart
_SESSION_COOKIE = "enclave_session"
_SESSIONS: dict = {}
_SESSION_LOCK = threading.Lock()
_SESSION_MAX_AGE = 12 * 3600
_DEFAULT_IDLE_MINUTES = 15
_LOGIN_FAILS: dict = {}
_LOGIN_MAX_FAILS = 5
_LOGIN_WINDOW = 300
_AUTH_PUBLIC_PATHS = {"/", "/api/health", "/api/auth/status", "/api/auth/login",
                      "/api/auth/logout", "/api/node/start", "/lan-login", _SMS_WEBHOOK}
_FIRST_RUN_PATHS = {"/api/identity/generate", "/api/identity/restore"}


def _now() -> float:
    return _time.time()


def _cookie_name() -> str:
    # Cookies are shared between ports of the same host, and every profile runs on
    # its own port. A per-port name stops one profile's login from clobbering another's.
    return _SESSION_COOKIE + (f"_{_PORT}" if _PORT else "")


def _idle_minutes() -> int:
    try:
        return max(0, int(app_core.config.get_setting("session_idle_minutes", _DEFAULT_IDLE_MINUTES)))
    except (TypeError, ValueError):
        return _DEFAULT_IDLE_MINUTES


def _session_from_request():
    sid = request.cookies.get(_cookie_name(), "")
    if not sid:
        return None
    now = _now()
    idle = _idle_minutes() * 60
    with _SESSION_LOCK:
        sess = _SESSIONS.get(sid)
        if sess is None:
            return None
        if now - sess["created"] > _SESSION_MAX_AGE or (idle and now - sess["last"] > idle):
            _SESSIONS.pop(sid, None)
            return None
        sess["last"] = now
        return dict(sess)


def _issue_session(resp, via: str):
    sid = secrets.token_urlsafe(32)
    now = _now()
    with _SESSION_LOCK:
        for k in [k for k, v in _SESSIONS.items() if now - v["created"] > _SESSION_MAX_AGE]:
            _SESSIONS.pop(k, None)
        _SESSIONS[sid] = {"created": now, "last": now, "via": via}
    resp.set_cookie(_cookie_name(), sid, httponly=True, samesite="Strict", path="/")
    return resp


def _drop_session(resp=None):
    sid = request.cookies.get(_cookie_name(), "")
    if sid:
        with _SESSION_LOCK:
            _SESSIONS.pop(sid, None)
    if resp is not None:
        resp.delete_cookie(_cookie_name(), path="/")
    return resp


def _login_attempts_left(ip: str) -> bool:
    now = _now()
    recent = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < _LOGIN_WINDOW]
    _LOGIN_FAILS[ip] = recent
    return len(recent) < _LOGIN_MAX_FAILS


@app.before_request
def _require_session():
    if not _AUTH_ENABLED:
        return
    path = request.path
    if path in _AUTH_PUBLIC_PATHS:
        return
    if _session_from_request():
        return
    # First run: with no identity yet there is nothing to log in to, so the person at
    # this computer may create (or restore) one. Never from another device.
    if (path in _FIRST_RUN_PATHS and not app_core.identity.has_identity()
            and _is_loopback(request.remote_addr)):
        return
    return jsonify({"error": "login required", "login": True}), 401


def _first_run_session(resp, first_run: bool):
    """Whoever just created (or restored) the identity on this computer is signed in."""
    if first_run and _AUTH_ENABLED and _is_loopback(request.remote_addr):
        return _issue_session(resp, "local")
    return resp


@app.route("/api/auth/status")
def auth_status():
    sess = _session_from_request() if _AUTH_ENABLED else {"via": "dev"}
    return jsonify({
        "has_identity": app_core.identity.has_identity(),
        "node_running": app_core.get_node() is not None,
        "authenticated": bool(sess),
        "login_required": _AUTH_ENABLED,
        "local": _is_loopback(request.remote_addr),
        "lan_mode": _LAN_MODE,
        "idle_minutes": _idle_minutes(),
    })


@app.route("/api/auth/settings")
def auth_settings_get():
    return jsonify({
        "idle_minutes": _idle_minutes(),
        "lock_on_page_load": bool(app_core.config.get_setting("lock_on_page_load", False)),
    })


@app.route("/api/auth/settings", methods=["POST"])
def auth_settings_set():
    data = request.get_json(force=True) or {}
    if "idle_minutes" in data:
        try:
            minutes = int(data["idle_minutes"])
        except (TypeError, ValueError):
            return err("idle_minutes must be a whole number", 400)
        if not 0 <= minutes <= 1440:
            return err("idle_minutes must be between 0 (never) and 1440", 400)
        app_core.config.set_setting("session_idle_minutes", minutes)
    if "lock_on_page_load" in data:
        app_core.config.set_setting("lock_on_page_load", bool(data["lock_on_page_load"]))
    return jsonify({"ok": True})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    return _drop_session(jsonify({"ok": True}))


# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    resp = make_response(render_template('chat.html', csrf_token=_CSRF_TOKEN))
    resp.headers["Cache-Control"] = "no-store"
    if _AUTH_ENABLED and app_core.config.get_setting("lock_on_page_load", False):
        _drop_session(resp)            # every fetch of the page asks for the passphrase again
    return resp

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

# -- Identity ----------------------------------------------------------------

@app.route("/api/identity")
@app.route("/api/identity/status")
def identity_status():
    return jsonify(app_core.get_identity_status())


@app.route("/api/identity/share")
def identity_share():
    info = app_core.get_share_info()
    try:
        import segno  # optional dependency, only needed for the QR image
        info["qr"] = bool(info["address"] or info["node_id"])
    except ImportError:
        info["qr"] = False
    return jsonify(info)


@app.route("/api/identity/share.svg")
def identity_share_svg():
    """QR code of this node's direct-connect address (ip:port), falling
    back to the node id. The new-chat box accepts either."""
    try:
        import segno
    except ImportError:
        return err("QR support needs the 'segno' package (pip install segno)", 501)
    info = app_core.get_share_info()
    text = info["address"] or info["node_id"]
    if not text:
        return err("no identity yet", 404)
    # NOT svg_inline(): that output is meant to be pasted into an HTML page and
    # has no xmlns, so a browser refuses to draw it as a standalone <img>
    # (the image shows as broken). save(kind="svg") writes a complete SVG
    # document with the namespace.
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2,
                                     dark="#111111", light="#ffffff")
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "image/svg+xml"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/identity/backup", methods=["POST"])
def identity_backup():
    try:
        return jsonify(app_core.export_identity_backup())
    except RuntimeError as e:
        return err(str(e), 404)


@app.route("/api/identity/restore", methods=["POST"])
def identity_restore():
    data = request.get_json(silent=True) or {}
    first_run = not app_core.identity.has_identity()
    try:
        res = app_core.restore_identity_backup(data.get("backup"), data.get("passphrase", ""))
        return _first_run_session(jsonify({"ok": True, **res}), first_run)
    except ValueError as e:
        return err(str(e), 400)


@app.route("/api/lan/status")
def lan_status():
    """Whether this instance is shared on the LAN. The access code is only
    ever revealed to a request coming from this machine itself."""
    out = {"lan_mode": _LAN_MODE}
    if _LAN_MODE and _is_loopback(request.remote_addr):
        out["code"] = _LAN_CODE
    return jsonify(out)


@app.route("/api/identity/update", methods=["POST"])
def identity_update():
    """Save display name (username) for the active profile."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    try:
        app_core.config.username = username
        return jsonify({"ok": True, "username": username,
                        "node_id": app_core.get_identity_status().get("node_id", "")})
    except Exception as e:
        return err(str(e), 500, exc=e)


@app.route("/api/identity/generate", methods=["POST"])
@app.route("/api/identity/regenerate", methods=["POST"])
def identity_generate():
    """Regenerate identity keypair.

    Passphrase resolution order:
      1. Explicit ``passphrase`` in request body (always accepted).
      2. Passphrase inferred from the already-unlocked identity in memory
         (node is running — re-use the session key so callers don't have to
         supply it again after unlock).
    """
    first_run = not app_core.identity.has_identity()
    data = request.get_json(force=True) or {}
    p = data.get("passphrase", "")

    # If node is already unlocked we can derive the passphrase from memory.
    # IdentityManager keeps a reference to the loaded private key; we ask it
    # to re-encrypt with the same passphrase it last loaded with.
    if not p:
        if app_core.identity.ed25519_priv is not None:
            # identity is loaded — re-save under same passphrase by letting
            # save_identity() use the cached value.
            try:
                app_core.identity.generate_new_identity()
                app_core.identity.save_identity()  # uses cached passphrase
                return jsonify({"node_id": app_core.identity.get_user_id()})
            except Exception as e:
                return err(str(e), 500, exc=e)
        return err("passphrase required", 400)

    try:
        app_core.identity.generate_new_identity()
        app_core.identity.save_identity(passphrase=p)
        return _first_run_session(jsonify({"node_id": app_core.identity.get_user_id()}), first_run)
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Node --------------------------------------------------------------------

_callbacks_registered = False


@app.route("/api/auth/login", methods=["POST"])
@app.route("/api/node/start", methods=["POST"])
def node_start():
    """Check the passphrase, start the node if it is not running, and sign this browser in."""
    if not _is_loopback(request.remote_addr):
        return err("Enter your passphrase on the computer that runs Enclave. It is never accepted "
                   "from other devices, because it would cross the network unencrypted.", 403)
    data = request.get_json(force=True) or {}
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    if not app_core.identity.has_identity():
        return err("no identity yet - create one first", 400)

    ip = request.remote_addr or "?"
    if not _login_attempts_left(ip):
        return err("too many wrong passphrases, try again in a few minutes", 429)
    if not app_core.identity.verify_passphrase(p):
        _LOGIN_FAILS.setdefault(ip, []).append(_now())
        return err("invalid passphrase", 403)
    _LOGIN_FAILS.pop(ip, None)

    try:
        if app_core.get_node() is None:
            app_core.start_node(passphrase=p)
            _register_node_callbacks()
        else:
            app_core.identity.load_identity(passphrase=p)
        resp = jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)
    return _issue_session(resp, "local") if _AUTH_ENABLED else resp


def _register_node_callbacks():
    global _callbacks_registered
    if _callbacks_registered:
        return
    node = app_core.get_node()
    if node is None:
        return

    def _ws_inbound(envelope: dict):
        _ws_broadcast("new_message", {
            "chat_id":   envelope.get("from", ""),
            "sender_id": envelope.get("from", ""),
            "ts":        envelope.get("ts", ""),
        })

    def _ws_peer(peer: dict):
        peer_data = dict(peer)
        peer_data["online"] = True
        peer_data["last_seen"] = datetime.now(timezone.utc).isoformat()
        _ws_broadcast("peer_update", {"peer": peer_data})

    def _ws_contact_request(info: dict):
        _ws_broadcast("contact_request", info)

    node.on_inbound_callbacks.append(_ws_inbound)
    node.on_peer_found_callbacks.append(_ws_peer)
    node.on_contact_request_callbacks.append(_ws_contact_request)
    _callbacks_registered = True

# -- Peers -------------------------------------------------------------------

@app.route("/api/peers")
def list_peers():
    raw = app_core.get_peers()
    return jsonify({"peers": _stamp_online(raw)})


@app.route("/api/peers/scan")
def scan_peers_route():
    try:
        # scan for the port OUR node listens on (peers on this LAN normally
        # use the same one); fall back to the default transport port
        port = app_core.config.get_setting("network_port") or ENCLAVE_PORT
        found = scan_lan_peers(app_core.peers, port=int(port))
        return jsonify({"peers": found, "count": len(found)})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Contacts (handshake) -----------------------------------------------

@app.route("/api/contacts/requests")
def contacts_requests():
    return jsonify({"requests": app_core.get_pending_contact_requests()})


@app.route("/api/contacts/request", methods=["POST"])
def contacts_request():
    data = request.get_json(force=True) or {}
    peer_id  = data.get("peer_id", "")
    greeting = data.get("greeting", "")
    if not peer_id:
        return err("peer_id required", 400)
    try:
        ok = app_core.send_contact_request(peer_id, greeting)
        return jsonify({"ok": ok})
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)


@app.route("/api/contacts/<path:peer_id>/accept", methods=["POST"])
def contacts_accept(peer_id):
    try:
        ok = app_core.accept_contact_request(peer_id)
        return jsonify({"ok": ok})
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)


@app.route("/api/contacts/<path:peer_id>/reject", methods=["POST"])
def contacts_reject(peer_id):
    try:
        app_core.reject_contact_request(peer_id)
        return jsonify({"ok": True})
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)


@app.route("/api/contacts/<path:peer_id>/nickname", methods=["POST"])
def contacts_nickname(peer_id):
    data = request.get_json(force=True) or {}
    ok = app_core.set_contact_nickname(peer_id, data.get("nickname", ""))
    if not ok:
        return err("unknown peer — discover or connect to them first", 404)
    return jsonify({"ok": True})


# -- Profile customization -----------------------------------------------

@app.route("/api/profile")
def profile_get():
    return jsonify(app_core.get_profile())


@app.route("/api/profile", methods=["POST"])
def profile_update():
    data = request.get_json(force=True) or {}
    try:
        if "status" in data:
            app_core.set_profile_status(data["status"])
        if "bio" in data:
            app_core.set_profile_bio(data["bio"])
        return jsonify(app_core.get_profile())
    except Exception as e:
        return err(str(e), 500, exc=e)


# -- Relay (store-and-forward) -------------------------------------------

@app.route("/api/relay/status")
def relay_status():
    return jsonify(app_core.get_relay_status())


@app.route("/api/relay/config", methods=["POST"])
def relay_config():
    data = request.get_json(force=True) or {}
    if "enabled" not in data:
        return err("enabled required", 400)
    try:
        app_core.set_relay_enabled(bool(data["enabled"]))
        return jsonify(app_core.get_relay_status())
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Crypto ------------------------------------------------------------------

@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    missing = {"passphrase", "plaintext", "chat_id", "created_at"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    try:
        token = app_core.encrypt_message(
            plaintext=data["plaintext"],
            chat_id=data["chat_id"],
            created_at=data["created_at"],
            passphrase=data["passphrase"],
        )
        return jsonify({"token": token})
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    data = request.get_json(force=True)
    if "passphrase" not in data or "token" not in data:
        return err("passphrase and token required", 400)
    try:
        pt = app_core.decrypt_message(
            token=data["token"],
            passphrase=data["passphrase"],
            chat_id=data.get("chat_id"),
        )
        return jsonify({"plaintext": pt})
    except Exception as e:
        return jsonify({"plaintext": None, "error": str(e)})

# -- Chats -------------------------------------------------------------------

@app.route("/api/chats")
def list_chats():
    return jsonify({"chats": app_core.get_chats()})

# Address-format classification for /api/chats/new lives in main.py's
# classify_address() — shared with tui.py's :new command, and it doesn't
# need Flask, so it doesn't belong in this file.

@app.route("/api/chats/new", methods=["POST"])
def new_chat():
    # This route did not exist at all before this fix. It's called by
    # BOTH the "+ new chat" modal AND clicking any peer in the peers list
    # (startChatWith()) — so starting a conversation with anyone, even an
    # already-discovered LAN peer, has been a guaranteed 404 until now.
    data = request.get_json(force=True)
    address = (data.get("address") or "").strip()
    name = (data.get("name") or "").strip() or None

    try:
        chat_id, addr_type = app_core.classify_address(address)
    except ValueError as e:
        return err(str(e), 400)

    if addr_type == "ip":
        # An ip:port isn't a chat_id — we have to ask that address who it
        # is first (GET /identity), then chat with whatever identity comes
        # back. Needs a running node, since it's a live network round trip.
        node = app_core.get_node()
        if node is None:
            return err("start the node first — connecting to an address needs it running", 409)
        try:
            peer = node.connect_to_address(address)
        except ValueError as e:
            return err(str(e), 400)
        except Exception as e:
            return err(f"could not connect to {address}: {e}", 502)
        if not peer:
            return err(f"no enclave node answered at {address}", 404)
        return jsonify({"chat_id": peer["user_id"], "type": "ip",
                        "username": peer.get("username", "")})

    if addr_type == "node" and name:
        existing = app_core.peers.get(chat_id)
        if existing and not existing.get("username"):
            app_core.peers.upsert(
                user_id=chat_id,
                username=name,
                ed25519_pub=existing.get("ed25519_pub", ""),
                x25519_pub=existing.get("x25519_pub", ""),
                ip=existing.get("ip", ""),
                port=existing.get("port", 0),
            )

    return jsonify({"chat_id": chat_id, "type": addr_type})

@app.route("/api/chats/<path:chat_id>")
def get_chat(chat_id):
    return jsonify({"chat_id": chat_id, "messages": app_core.get_messages(chat_id)})

# ---------------------------------------------------------------------------
# Plugin trust
# ---------------------------------------------------------------------------
# User-installed plugins are arbitrary Python with the same access you have
# (files, network, your identity key). Manifest permissions do NOT sandbox
# them. They are therefore never loaded until trusted here, and trust is
# pinned to the exact main.py hash so editing the file revokes it.

def _public_plugin_info(info: dict) -> dict:
    """Plugin settings can hold secrets (e.g. the SMS gateway password).
    The UI never needs to read them back, so blank any password field."""
    info = dict(info)
    schema = info.get("schema") or []
    secret_keys = {f.get("key") for f in schema
                   if isinstance(f, dict) and f.get("type") == "password"}
    if secret_keys and isinstance(info.get("settings"), dict):
        info["settings"] = {k: ("" if k in secret_keys else v)
                            for k, v in info["settings"].items()}
    return info


@app.route("/api/plugins")
def list_plugins():
    return jsonify({"plugins": [_public_plugin_info(p)
                                for p in app_core.plugin_manager.get_all()]})


@app.route("/api/plugins/<plugin_id>/enable", methods=["POST"])
def enable_plugin(plugin_id):
    return jsonify(app_core.plugin_manager.enable(plugin_id))


@app.route("/api/plugins/<plugin_id>/disable", methods=["POST"])
def disable_plugin(plugin_id):
    return jsonify(app_core.plugin_manager.disable(plugin_id))


@app.route("/api/plugins/<plugin_id>/trust", methods=["POST"])
def trust_plugin(plugin_id):
    data = request.get_json(silent=True) or {}
    if data.get("i_understand") is not True:
        return jsonify({
            "ok": False,
            "error": "confirmation required: this plugin will be able to run "
                     "any code with your privileges. Send i_understand: true.",
        }), 400
    return jsonify(app_core.plugin_manager.trust(plugin_id))


@app.route("/api/plugins/<plugin_id>/untrust", methods=["POST"])
def untrust_plugin(plugin_id):
    return jsonify(app_core.plugin_manager.untrust(plugin_id))


@app.route("/api/messages/<path:chat_id>")
def get_messages_decrypted(chat_id):
    # This is the route the frontend actually calls (refreshMessages() in
    # chat.html) — it did not exist at all before this fix, so every
    # "open a chat" request 404'd. Separately, /api/chats/<id> above never
    # decrypted anything (it hands back raw ciphertext tokens) and nothing
    # in the frontend ever called /api/crypto/decrypt either — so even with
    # a matching URL, messages would have rendered as raw ciphertext.
    # Actual decrypt+resolve logic lives in main.py (shared with tui.py).
    #
    # The passphrase used to arrive as ?passphrase=... — URLs are written
    # to access logs (werkzeug prints the full request line to the
    # terminal), browser/proxy history and Referer headers, so a secret
    # must never live there. It now travels in a request header instead.
    # It is percent-encoded by the client because HTTP header values must
    # be Latin-1 and passphrases are free-form unicode.
    if "passphrase" in request.args:
        return jsonify({
            "error": "passphrase must be sent in the "
                     f"{_PASSPHRASE_HEADER} header, not the URL"
        }), 400
    passphrase = unquote(request.headers.get(_PASSPHRASE_HEADER, ""))
    return jsonify({
        "chat_id": chat_id,
        "messages": app_core.get_messages_decrypted(chat_id, passphrase),
    })

@app.route("/api/chats/<path:chat_id>/append", methods=["POST"])
def append_to_chat(chat_id):
    data  = request.get_json(force=True)
    token = data.get("token", "")
    if not token:
        return err("token required", 400)
    app_core.chats.append_message(chat_id, {
        "token":  token,
        "sender": data.get("sender"),
        "ts":     data.get("ts"),
    })
    return jsonify({"status": "ok"})

@app.route("/api/chats/<path:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    app_core.chats.delete_chat(chat_id)
    return jsonify({"status": "deleted"})

# -- Network message send ----------------------------------------------------

@app.route("/api/message/send", methods=["POST"])
def message_send():
    data = request.get_json(force=True)
    peer_id   = data.get("peer_id", "")
    plaintext = data.get("plaintext", "")
    if not peer_id or not plaintext:
        return err("peer_id and plaintext required", 400)
    try:
        ok = app_core.send_message(peer_id, plaintext)
        return jsonify({"ok": ok})
    except ValueError as e:
        return err(str(e), 400)
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/message/retry", methods=["POST"])
def message_retry():
    data = request.get_json(force=True)
    peer_id = data.get("peer_id", "")
    ts = data.get("ts", "")
    if not peer_id or not ts:
        return err("peer_id and ts required", 400)
    try:
        return jsonify({"ok": app_core.retry_message(peer_id, ts)})
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- SMS ---------------------------------------------------------------------

@app.route("/api/sms/config", methods=["POST"])
def sms_config():
    data = request.get_json(force=True)
    missing = {"username", "password"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    app_core.configure_sms(
        username=data["username"],
        password=data["password"],
        host=data.get("host"),
    )
    return jsonify({"status": "saved"})


@app.route("/api/sms/pairing-code")
def sms_pairing_code():
    try:
        return jsonify(app_core.get_sms_pairing_code())
    except RuntimeError as e:
        return err(str(e), 409)


@app.route("/api/sms/pair", methods=["GET", "POST", "DELETE"])
def sms_pair():
    if request.method == "GET":
        try:
            return jsonify(app_core.get_sms_pair(request.args.get("phone", "")))
        except ValueError as e:
            return err(str(e), 400)

    data = request.get_json(silent=True) or {}
    phone = data.get("phone", "")
    try:
        if request.method == "DELETE":
            return jsonify(app_core.unpair_sms_chat(phone))
        code = data.get("pairing_code", "")
        return jsonify(app_core.pair_sms_chat(phone, code))
    except ValueError as e:
        return err(str(e), 400)
    except RuntimeError as e:
        return err(str(e), 409)


@app.route(_SMS_WEBHOOK, methods=["POST"])
def sms_webhook():
    """Incoming SMS from the android-sms-gateway app. Signed; see core/sms_inbound.py."""
    key = app_core.config.get_setting("sms_signing_key", "")
    if not key:
        return err("incoming SMS is not set up (no signing key)", 503)
    limit = sms_inbound.MAX_BODY_BYTES
    if request.content_length and request.content_length > limit:
        return err("body too large", 413)
    raw = request.stream.read(limit + 1)
    if len(raw) > limit:
        return err("body too large", 413)
    if not sms_inbound.verify_signature(key, raw, request.headers.get("X-Timestamp", ""),
                                        request.headers.get("X-Signature", "")):
        app_core.log.warning("[sms] webhook rejected: bad or missing signature")
        return err("invalid signature", 401)
    try:
        event = sms_inbound.parse_received(raw)
    except ValueError as e:
        return err(str(e), 400)
    if event is None:
        return jsonify({"status": "ignored"})              # some other event type: acknowledge it
    try:
        chat_id = sms_inbound.sender_chat_id(event["sender"])
    except ValueError:
        return jsonify({"status": "ignored"})              # a sender we cannot make a chat for
    try:
        result = app_core.receive_sms(chat_id, event["message"], event["ext_id"], event["received_at"])
    except RuntimeError as e:
        return err(str(e), 503)                            # locked: the gateway app retries later
    except ValueError as e:
        app_core.log.warning(f"[sms] rejected encrypted message from {chat_id}: {e}")
        return err(str(e), 400)
    if result == "stored":
        _ws_broadcast("new_message", {"chat_id": chat_id, "sender_id": chat_id,
                                      "ts": datetime.now(timezone.utc).isoformat()})
    return jsonify({"status": result})


@app.route("/api/sms/inbound")
def sms_inbound_get():
    return jsonify({**app_core.sms_inbound_status(), "webhook_path": _SMS_WEBHOOK})


@app.route("/api/sms/inbound", methods=["POST"])
def sms_inbound_set():
    data = request.get_json(force=True) or {}
    key = str(data.get("signing_key", "")).strip()
    if key and not 8 <= len(key) <= 200:
        return err("the signing key looks wrong (copy it from the phone app: Settings > Webhooks)", 400)
    app_core.set_sms_signing_key(key)
    return jsonify({"ok": True, **app_core.sms_inbound_status()})


@app.route("/api/sms/inbound/register", methods=["POST"])
def sms_inbound_register():
    """Ask the gateway app to deliver incoming SMS to `url`."""
    data = request.get_json(force=True) or {}
    url = str(data.get("url", "")).strip()
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
        ok = (parts.scheme in ("http", "https") and parts.hostname and not parts.username
              and not parts.password and parts.path.rstrip("/") == _SMS_WEBHOOK and len(url) <= 300)
    except ValueError:
        ok = False
    if not ok:
        return err(f"the URL must end in {_SMS_WEBHOOK}", 400)
    if not app_core.config.get_setting("sms_signing_key", ""):
        return err("save the signing key first, otherwise every incoming text would be refused", 400)
    try:
        return jsonify({"ok": True, "gateway": app_core.register_sms_webhook(url)})
    except Exception as e:
        return err(f"the gateway did not accept it: {e}", 502)


@app.route("/api/config/save", methods=["POST"])
def config_save():
    """Frontend alias for saving SMS gateway config.

    The Settings panel POSTs {sms_user, sms_pass, sms_host} to this endpoint;
    we normalise the field names and delegate to configure_sms().
    """
    data = request.get_json(force=True) or {}
    username = data.get("sms_user", "").strip()
    password = data.get("sms_pass", "").strip()
    host     = data.get("sms_host", "").strip() or None
    if not username and not password:
        # Nothing to save — return ok anyway so the UI doesn't flash an error.
        return jsonify({"status": "ok"})
    try:
        app_core.configure_sms(username=username, password=password, host=host)
        return jsonify({"status": "saved"})
    except Exception as e:
        return err(str(e), 500, exc=e)


@app.route("/api/config/dht")
def get_dht_config():
    return jsonify({
        "dht_enabled": app_core.config.get_setting("dht_enabled", False),
        "dht_bootstrap": app_core.config.get_setting("dht_bootstrap", []),
        "dht_public_ip": app_core.config.get_setting("dht_public_ip", "") or "",
        # Whether DHT is ACTUALLY running right now, vs just configured —
        # these can differ, since config changes take effect on the next
        # node start, not live on an already-running node.
        "dht_active": bool(app_core.get_identity_status().get("dht_active")),
    })


_BOOTSTRAP_ADDR_RE = re.compile(r'^[^\s:]+:\d{1,5}$')

@app.route("/api/config/dht", methods=["POST"])
def save_dht_config():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("dht_enabled", False))

    bootstrap_raw = data.get("dht_bootstrap", "")
    if isinstance(bootstrap_raw, str):
        candidates = [b.strip() for b in re.split(r'[,\n]', bootstrap_raw) if b.strip()]
    else:
        candidates = [str(b).strip() for b in (bootstrap_raw or []) if str(b).strip()]

    bad = [b for b in candidates if not _BOOTSTRAP_ADDR_RE.match(b)]
    if bad:
        return err(f"invalid bootstrap address (expected host:port): {bad[0]!r}", 400)

    public_ip = (data.get("dht_public_ip") or "").strip()

    app_core.config.set_setting("dht_enabled", enabled)
    app_core.config.set_setting("dht_bootstrap", candidates)
    app_core.config.set_setting("dht_public_ip", public_ip or None)

    return jsonify({
        "ok": True,
        "dht_enabled": enabled,
        "dht_bootstrap": candidates,
        "dht_public_ip": public_ip,
        "note": "takes effect the next time the node is started, not live on an already-running node",
    })


def sms_send():
    data = request.get_json(force=True)
    if "to" not in data or "message" not in data:
        return err("to and message required", 400)
    try:
        return jsonify(app_core.send_sms(data["to"], data["message"]))
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/sms/status/<message_id>")
def sms_status(message_id):
    try:
        from enclave_messenger.core.plugins import SMSGateway
        return jsonify(SMSGateway.from_config(app_core.config).get_status(message_id))
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Bluetooth ---------------------------------------------------------------

@app.route("/api/bt/scan")
def bt_scan():
    try:
        duration = int(request.args.get("duration", 8))
    except (ValueError, TypeError):
        duration = 8
    try:
        devices = app_core.scan_bluetooth(duration=duration)
        return jsonify({"devices": devices, "count": len(devices)})
    except BluetoothUnavailableError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)


# -- Profiles ----------------------------------------------------------------

@app.route("/api/profiles")
def profiles_list():
    return jsonify({"profiles": _profiles.list_profiles()})


@app.route("/api/profiles", methods=["POST"])
def profiles_create():
    # This used to only write a registry entry (name + ports) — no
    # identity, and nothing actually listening on the new profile's
    # port. The profile showed up in the list with a URL that just
    # connection-refused, because nothing was running there, and even
    # if something had been, there was no identity to unlock. Now:
    # create the registry entry, generate + save a real identity for it,
    # and set its username so it's not blank when discovered — all via
    # app_core.create_profile_with_identity(), the ONE place that knows
    # how to do this correctly. (This route used to have its own inline
    # copy of that logic. Duplicating it was exactly how tui.py's
    # :new-profile ended up calling a function that didn't exist yet —
    # two surfaces with two different ideas of "how to create a
    # profile." Not duplicating it anymore.)
    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    passphrase = data.get("passphrase", "")
    if not name:
        return err("name required", 400)
    if not passphrase:
        return err("passphrase required — a profile with no identity can't be unlocked later", 400)

    try:
        profile = app_core.create_profile_with_identity(
            name=name, passphrase=passphrase,
            username=data.get("username"),
            transport_port=data.get("transport_port"),
            web_port=data.get("web_port"),
        )
    except ValueError as e:
        return err(str(e), 409)
    except Exception as e:
        return err(
            f"profile registered but identity creation failed: {e}. "
            f"Delete '{name}' and try again.", 500,
        )

    process_started = False
    process_error = None
    process_pid = None
    try:
        proc = spawn_web_profile(name, profile["web_port"])
        process_started = True
        process_pid = proc.pid
        # Print to the terminal that launched THIS server, so there's a
        # durable record of the child's pid: the browser status line is
        # gone on the next page load, and you need that pid to stop the
        # profile later. Same behaviour as tui.py's :new-profile.
        print(f"[enclave] started profile '{name}' on port {profile['web_port']} "
              f"— pid {proc.pid}", flush=True)
    except OSError as e:
        process_error = str(e)

    profile["process_started"] = process_started
    profile["pid"] = process_pid
    if not process_started:
        profile["process_error"] = (
            f"{process_error} — identity was created successfully, but you'll need "
            f"to start it yourself: python3 web.py --profile {name} --port {profile['web_port']}"
        )
    return jsonify(profile), 201


@app.route("/api/profiles/active")
def profiles_get_active():
    name = _profiles.get_active_profile()
    if not name:
        return jsonify({"active": None})
    return jsonify({"active": name, "profile": _profiles.get_profile(name)})


@app.route("/api/profiles/<pname>/activate", methods=["POST"])
def profiles_activate(pname):
    try:
        p = _profiles.set_active_profile(pname)
        return jsonify(p)
    except ValueError as e:
        return err(str(e), 404)


@app.route("/api/profiles/<pname>", methods=["PATCH"])
def profiles_rename(pname):
    data = request.get_json(force=True)
    new_name = data.get("name", "").strip()
    if not new_name:
        return err("new name required", 400)
    try:
        return jsonify(_profiles.rename_profile(pname, new_name))
    except ValueError as e:
        return err(str(e), 409)


@app.route("/api/profiles/<pname>", methods=["DELETE"])
def profiles_delete(pname):
    if not _profiles.delete_profile(pname):
        return err(f"Profile '{pname}' not found", 404)
    return jsonify({"status": "deleted", "name": pname})


@app.route("/api/profiles/<pname>")
def profiles_get(pname):
    p = _profiles.get_profile(pname)
    if p is None:
        return err(f"Profile '{pname}' not found", 404)
    return jsonify(p)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

if _SOCK_AVAILABLE:
    @_sock.route("/ws")
    def ws_handler(ws):
        # WebSocket handshakes are NOT covered by CORS/preflight — a page
        # on any origin can open ws://127.0.0.1:PORT/ws directly and the
        # browser will happily complete the handshake. Without an explicit
        # check here, any website you have open could silently connect and
        # receive the 'init' frame below (identity status, full peer list,
        # every chat id) plus live message/peer events. Reject anything
        # whose declared Origin doesn't match this server's own host; allow
        # requests with no Origin header at all (non-browser clients like a
        # future CLI/TUI, curl, etc., which don't send one).
        origin = request.headers.get("Origin", "")
        if origin:
            from urllib.parse import urlparse
            if urlparse(origin).netloc != request.host:
                log = getattr(app_core, "log", None)
                if log:
                    log.warning("[ws] rejected cross-origin connection from %r", origin)
                return ""  # closes the handshake without upgrading

        with _ws_lock:
            _ws_clients.append(ws)
        try:
            ws.send(_json.dumps({
                "event":    "init",
                "peers":    _stamp_online(app_core.get_peers()),
                "chats":    app_core.get_chats(),
                "identity": app_core.get_identity_status(),
                "contact_requests": app_core.get_pending_contact_requests(),
            }))
            while True:
                msg = ws.receive(timeout=30)
                if msg is None:
                    break
                try:
                    frame = _json.loads(msg)
                    if frame.get("type") == "ping":
                        ws.send(_json.dumps({"event": "pong"}))
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            with _ws_lock:
                try:
                    _ws_clients.remove(ws)
                except ValueError:
                    pass


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def select_profile(profile_arg):
    """Switch app_core to another profile. Must run before any state is used."""
    if profile_arg:
        app_core.config, app_core.chats, app_core.peers, \
        app_core.identity, app_core.log, app_core._active_profile = \
            app_core._init_stores(profile_arg)
        app_core.plugin_manager.discover()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pe-em web", description="Enclave Messenger web UI")
    parser.add_argument(
        "--host",
        choices=["host", "lan"],
        default=None,
        help="Bind target: 'host' (127.0.0.1) or 'lan' (0.0.0.0). "
             "Falls back to ENCLAVE_HOST env var, then defaults to 'host'.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Web UI port to bind on. Overrides profile web_port and config. "
             "Falls back to ENCLAVE_PORT env var, then profile web_port, then 5000.",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Profile to load. Falls back to ENCLAVE_PROFILE env var, "
             "then the active profile in registry.json.",
    )
    args = parser.parse_args(argv)

    # Profile override: must happen before any app_core state is used
    select_profile(args.profile or os.environ.get("ENCLAVE_PROFILE"))

    bind_mode = args.host or os.environ.get("ENCLAVE_HOST", "host")
    bind_ip   = "0.0.0.0" if bind_mode == "lan" else "127.0.0.1"

    # Port resolution order: --port flag > ENCLAVE_PORT env > profile web_port > config > 5000
    profile_meta = _profiles.get_profile(app_core._active_profile)
    profile_web_port = (profile_meta or {}).get("web_port")
    port = (
        args.port
        or int(os.environ.get("ENCLAVE_PORT", 0)) or None
        or profile_web_port
        or app_core.config.get_setting("port", 5000)
    )

    debug = app_core.config.get_setting("debug", False)

    if bind_mode == "lan":
        # Werkzeug's debugger console is remote code execution for anyone
        # who can reach the port, so it is never allowed on a LAN bind.
        if debug:
            print(" ! debug mode is disabled while bound to the LAN")
            debug = False
        code = _enable_lan_mode()
        print("")
        print(" ! LAN mode: anyone on this network can reach this page.")
        print(f" ! Other devices must enter this access code:  {code}")
        print(" ! (this machine, via 127.0.0.1, is never asked for it)")
        print("")

    print(f" * Binding to {bind_ip}:{port}  (profile: {app_core._active_profile})")
    global _PORT
    _PORT = port
    app.run(host=bind_ip, port=port, debug=debug)


if __name__ == "__main__":
    main()
