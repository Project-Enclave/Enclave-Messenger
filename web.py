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
import os
import threading
import traceback
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template
try:
    from flask_sock import Sock
    _SOCK_AVAILABLE = True
except ImportError:
    _SOCK_AVAILABLE = False

import main as app_core
from core import profiles as _profiles
from core.network.scanner import scan_lan_peers, ENCLAVE_PORT
from core.plugins.builtin.bluetooth.main import BluetoothUnavailableError

app = Flask(__name__)

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
    if exc:
        p["detail"] = traceback.format_exc()
    return jsonify(p), code

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template('chat.html')

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

# -- Identity ----------------------------------------------------------------

@app.route("/api/identity")
@app.route("/api/identity/status")
def identity_status():
    return jsonify(app_core.get_identity_status())


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
        return jsonify({"node_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Node --------------------------------------------------------------------

_callbacks_registered = False


@app.route("/api/node/start", methods=["POST"])
def node_start():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)

    if app_core.get_node() is not None:
        try:
            app_core.identity.load_identity(passphrase=p)
        except Exception:
            return err("invalid passphrase", 403)
        return jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})

    try:
        app_core.start_node(passphrase=p)
        _register_node_callbacks()
        return jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)


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

    node.on_inbound_callbacks.append(_ws_inbound)
    node.on_peer_found_callbacks.append(_ws_peer)
    _callbacks_registered = True

# -- Peers -------------------------------------------------------------------

@app.route("/api/peers")
def list_peers():
    raw = app_core.get_peers()
    return jsonify({"peers": _stamp_online(raw)})


@app.route("/api/peers/scan")
def scan_peers_route():
    try:
        found = scan_lan_peers(app_core.peers)
        return jsonify({"peers": found, "count": len(found)})
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

@app.route("/api/chats/<path:chat_id>")
def get_chat(chat_id):
    return jsonify({"chat_id": chat_id, "messages": app_core.get_messages(chat_id)})

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


@app.route("/api/sms/send", methods=["POST"])
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
        from core.plugins import SMSGateway
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
    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    if not name:
        return err("name required", 400)
    try:
        profile = _profiles.create_profile(
            name=name,
            username=data.get("username"),
            transport_port=data.get("transport_port"),
            web_port=data.get("web_port"),
        )
        return jsonify(profile), 201
    except ValueError as e:
        return err(str(e), 409)


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
        with _ws_lock:
            _ws_clients.append(ws)
        try:
            ws.send(_json.dumps({
                "event":    "init",
                "peers":    _stamp_online(app_core.get_peers()),
                "chats":    app_core.get_chats(),
                "identity": app_core.get_identity_status(),
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enclave Messenger web UI")
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
    args = parser.parse_args()

    # Profile override: must happen before any app_core state is used
    profile_arg = args.profile or os.environ.get("ENCLAVE_PROFILE")
    if profile_arg:
        app_core.config, app_core.chats, app_core.peers, \
        app_core.identity, app_core.log, app_core._active_profile = \
            app_core._init_stores(profile_arg)
        app_core.plugin_manager.discover()

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

    print(f" * Binding to {bind_ip}:{port}  (profile: {app_core._active_profile})")
    app.run(host=bind_ip, port=port, debug=debug)
