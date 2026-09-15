"""
transport.py — HTTP transport layer.

Inbound:  a tiny Flask-compatible WSGI app that receives messages POSTed
          by remote peers to  POST /inbound
          (run in a background thread via wsgiref)

Outbound: send_message() does a plain HTTP POST to the peer's address.

Endpoints:
  POST /inbound   receive an encrypted message envelope
  GET  /health    liveness check — returns 200 {"ok": true}

Message envelope POSTed over the wire:
  {
    "from":    str,   # sender user_id
    "chat_id": str,   # usually the recipient's user_id
    "token":   str,   # CryptoManager.encrypt() output
    "ts":      str,   # ISO-8601
  }
"""

import json
import logging
import threading
from datetime import datetime, timezone
from wsgiref.simple_server import make_server, WSGIRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlencode

log = logging.getLogger("network")

_HEALTH_RESP = b'{"ok": true}'
_MAX_BODY_BYTES = 256 * 1024  # reject anything bigger — a text envelope has no business being large


class _SilentHandler(WSGIRequestHandler):
    """Suppress the default wsgiref access log."""
    def log_message(self, fmt, *args):
        log.debug("[transport] %s", fmt % args)


class Transport:
    def __init__(self, host: str, port: int, on_message, identity_provider=None):
        """
        host: bind address for inbound server, e.g. '0.0.0.0'
        port: listen port
        on_message: callback(envelope: dict) called for each valid inbound message
        identity_provider: optional callable returning this node's public
            identity dict, served at GET /identity. That endpoint is what
            makes manual "connect to ip:port" possible at all: without it
            there's no way to learn who is at an address, and a chat_id
            has to be a real user_id for encryption to work. Only public
            material is ever exposed here — the same fields already
            broadcast to the whole LAN by discovery.
        """
        self._host = host
        self._port = port
        self._on_message = on_message
        self._identity_provider = identity_provider
        self._server = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # ------------------------------------------------------------------
    # Inbound server
    # ------------------------------------------------------------------

    def start(self):
        self._server = make_server(
            self._host, self._port, self._wsgi_app,
            handler_class=_SilentHandler,
        )
        log.info("[transport] listening on %s:%d", self._host, self._port)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()

    def _serve(self):
        self._server.serve_forever()

    def _wsgi_app(self, environ, start_response):
        path   = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "")

        if method == "GET" and path == "/health":
            start_response("200 OK", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(_HEALTH_RESP))),
            ])
            return [_HEALTH_RESP]

        if method == "GET" and path == "/identity":
            if self._identity_provider is None:
                start_response("404 Not Found", [("Content-Length", "0")])
                return [b""]
            try:
                payload = json.dumps(self._identity_provider()).encode("utf-8")
            except Exception as e:
                log.warning("[transport] /identity failed: %s", e)
                start_response("500 Internal Server Error", [("Content-Length", "0")])
                return [b""]
            start_response("200 OK", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
            ])
            return [payload]

        if method == "POST" and path == "/inbound":
            try:
                # CONTENT_LENGTH may be an empty string — coerce safely
                length = int(environ.get("CONTENT_LENGTH") or 0)
                if length > _MAX_BODY_BYTES:
                    log.warning("[transport] inbound rejected: body too large (%d bytes)", length)
                    resp = json.dumps({"error": "payload too large"}).encode()
                    start_response("413 Payload Too Large", [
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(resp))),
                    ])
                    return [resp]
                body   = environ["wsgi.input"].read(length)
                envelope = json.loads(body.decode("utf-8"))
                self._on_message(envelope)
                status = "200 OK"
                resp   = b'{"ok": true}'
            except Exception as e:
                log.warning("[transport] inbound error: %s", e)
                status = "400 Bad Request"
                resp   = json.dumps({"error": str(e)}).encode()
        else:
            status = "404 Not Found"
            resp   = b"not found"

        start_response(status, [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(resp))),
        ])
        return [resp]

    # ------------------------------------------------------------------
    # Outbound client
    # ------------------------------------------------------------------

    def send(self, peer_address: str, envelope: dict) -> bool:
        """
        POST envelope to peer_address/inbound.
        Returns True on success, False on failure.
        """
        url  = f"{peer_address}/inbound"
        body = json.dumps(envelope).encode("utf-8")
        req  = Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as resp:
                log.debug("[transport] sent to %s -> %d", url, resp.status)
                return resp.status == 200
        except URLError as e:
            log.warning("[transport] send failed to %s: %s", url, e)
            return False

    def fetch_identity(self, peer_address: str) -> dict | None:
        """
        GET peer_address/identity — asks whoever is listening there who
        they are. Returns the identity dict, or None if nothing answered,
        it wasn't an enclave node, or the response wasn't usable.

        Deliberately strict about what counts as a valid answer: a random
        HTTP server on that port will not have these fields, and we'd
        rather report "no enclave node there" than half-register a peer
        we can't actually encrypt to.
        """
        url = f"{peer_address}/identity"
        try:
            with urlopen(Request(url), timeout=5) as resp:
                if resp.status != 200:
                    return None
                data = json.loads(resp.read(65536).decode("utf-8"))
        except (URLError, json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            log.info("[transport] identity fetch failed for %s: %s", url, e)
            return None

        if not isinstance(data, dict):
            return None
        required = ("user_id", "ed25519_pub", "x25519_pub")
        if not all(isinstance(data.get(k), str) and data.get(k) for k in required):
            log.info("[transport] %s answered but isn't an enclave node "
                      "(missing identity fields)", url)
            return None
        return data

    def is_alive(self, peer_address: str) -> bool:
        """
        Quick liveness check against peer_address/health.
        Returns True if the peer's transport server responds 200.
        """
        url = f"{peer_address}/health"
        req = Request(url)
        try:
            with urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except URLError:
            return False
