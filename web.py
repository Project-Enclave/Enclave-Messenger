"""
web.py — Enclave Messenger browser UI.
Run with: python web.py

This file only handles HTTP ↔ browser.
The actual logic for crypto and comms is NOT handled by this file.
"""

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
from core.network.scanner import scan_lan_peers, ENCLAVE_PORT

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

# A peer is considered stale after this many seconds without a heartbeat.
# discovery.py broadcasts every 30 s; we allow 1 missed interval and a 10 s delay → 40.
_PEER_STALE_SECONDS = 40


def _stamp_online(peers: list) -> list:
    """
    Annotate each peer dict with an ``online`` boolean.

    A peer is considered online if its ``last_seen`` timestamp is within the
    last _PEER_STALE_SECONDS seconds.  Peers that have never been seen (no
    ``last_seen`` field) or whose timestamp cannot be parsed are marked offline.
    """
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

@app.route("/api/identity/status")
def identity_status():
    return jsonify(app_core.get_identity_status())

@app.route("/api/identity/generate", methods=["POST"])
def identity_generate():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    try:
        app_core.identity.generate_new_identity()
        app_core.identity.save_identity(passphrase=p)
        return jsonify({"user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Node --------------------------------------------------------------------

@app.route("/api/node/start", methods=["POST"])
def node_start():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    try:
        app_core.start_node(passphrase=p)
        _patch_node_callbacks()
        return jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)


def _patch_node_callbacks():
    node = app_core.get_node()
    if node is None:
        return
    _orig_inbound = node._on_inbound
    def _ws_inbound(envelope: dict):
        _orig_inbound(envelope)
        _ws_broadcast("new_message", {
            "chat_id":   envelope.get("from", ""),
            "sender_id": envelope.get("from", ""),
            "ts":        envelope.get("ts", ""),
        })
    node._on_inbound = _ws_inbound

    _orig_peer = node._on_peer_found
    def _ws_peer(peer: dict):
        _orig_peer(peer)
        from datetime import datetime, timezone
        peer_data = dict(peer)
        peer_data["online"] = True
        peer_data["last_seen"] = datetime.now(timezone.utc).isoformat()
        _ws_broadcast("peer_update", {"peer": peer_data})
    node._on_peer_found = _ws_peer

# -- Peers -------------------------------------------------------------------

@app.route("/api/peers")
def list_peers():
    raw = app_core.get_peers()
    return jsonify({"peers": _stamp_online(raw)})


@app.route("/api/peers/scan")
def scan_peers_route():
    """Scan the local LAN subnet for Enclave peers on port 5001."""
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
    port  = app_core.config.get_setting("port", 5000)
    debug = app_core.config.get_setting("debug", False)
    host_ip=str(input("Where do you want to run this? (host/lan?): "))
    if host_ip=="host" or host_ip=="localhost" or host_ip=="127.0.0.1":
        app.run(host="127.0.0.1", port=port, debug=debug)
    elif host_ip=="lan" or host_ip=="0.0.0.0":
        app.run(host="0.0.0.0", port=port, debug=debug)
    else:
        print("Error: Invalid option! falling back to host")
        app.run(host="0.0.0.0", port=port, debug=debug)
