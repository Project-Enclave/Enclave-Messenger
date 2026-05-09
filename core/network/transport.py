"""
transport.py — HTTP transport layer.

Inbound:  a tiny Flask-compatible WSGI app that receives messages POSTed
          by remote peers to  POST /inbound
          (run in a background thread via wsgiref)

Outbound: send_message() does a plain HTTP POST to the peer's address.

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


class _SilentHandler(WSGIRequestHandler):
    """Suppress the default wsgiref access log."""
    def log_message(self, fmt, *args):
        log.debug("[transport] %s", fmt % args)


class Transport:
    def __init__(self, host: str, port: int, on_message):
        """
        host: bind address for inbound server, e.g. '0.0.0.0'
        port: listen port
        on_message: callback(envelope: dict) called for each valid inbound message
        """
        self._host = host
        self._port = port
        self._on_message = on_message
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

        if method == "POST" and path == "/inbound":
            try:
                length = int(environ.get("CONTENT_LENGTH", 0))
                body   = environ["wsgi.input"].read(length)
                envelope = json.loads(body.decode("utf-8"))
                self._on_message(envelope)
                status = "200 OK"
                resp   = b"{\"ok\": true}"
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
