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
from urllib.request import urlopen, Request, build_opener, HTTPRedirectHandler
from urllib.error import URLError
from urllib.parse import urlencode

log = logging.getLogger("network")

_HEALTH_RESP = b'{"ok": true}'
_MAX_BODY_BYTES = 256 * 1024  # reject anything bigger — a text envelope has no business being large



# ----------------------------------------------------------------------
# Outbound address validation
# ----------------------------------------------------------------------
# Peer addresses are built from "ip" / "port" values that other peers
# (via the DHT, discovery packets, relays) hand us, so they are
# attacker-influenced. Without checks, a malicious peer can make this
# node fire requests at arbitrary hosts, other URL schemes (file://,
# ftp://), cloud metadata endpoints (169.254.169.254), or smuggle a
# path/query into the URL we build.
#
# LAN / loopback / private addresses are deliberately still allowed:
# that is where legitimate peers live. What we do is shrink the
# attack surface to "one of four fixed paths (/inbound, /relay,
# /identity, /health) on a plain http(s) host:port" and block the
# ranges that are never a legitimate peer.

import ipaddress
import socket
import re as _re
from urllib.parse import urlsplit

_HOSTNAME_RE = _re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _ip_is_blocked(ip) -> bool:
    """True for addresses that can never be a legitimate peer."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if (ip.is_unspecified or ip.is_multicast or ip.is_link_local
            or ip.is_reserved):
        return True
    # 0.0.0.0/8 ("this network") — is_unspecified only covers 0.0.0.0
    if ip.version == 4 and int(ip) >> 24 == 0:
        return True
    return False


def validate_peer_address(address: str) -> bool:
    """
    True only if `address` is exactly http(s)://host:port with a
    non-blocked host. No credentials, path, query or fragment.
    """
    if not isinstance(address, str) or len(address) > 300:
        return False
    try:
        parts = urlsplit(address)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    if parts.username or parts.password:
        return False
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return False
    host = parts.hostname
    if not host or port is None or not (0 < port < 65536):
        return False

    try:
        return not _ip_is_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass  # not an IP literal — treat as a hostname

    if not _HOSTNAME_RE.match(host):
        return False
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        try:
            if _ip_is_blocked(ipaddress.ip_address(info[4][0].split("%")[0])):
                return False
        except ValueError:
            return False
    return True


class _NoRedirect(HTTPRedirectHandler):
    """A peer must not be able to bounce us to somewhere else."""
    def redirect_request(self, *args, **kwargs):
        return None


_opener = build_opener(_NoRedirect)


def _open(req, timeout):
    return _opener.open(req, timeout=timeout)


class _SilentHandler(WSGIRequestHandler):
    """Suppress the default wsgiref access log."""
    def log_message(self, fmt, *args):
        log.debug("[transport] %s", fmt % args)


class Transport:
    def __init__(self, host: str, port: int, on_message, identity_provider=None,
                 on_relay=None):
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
        on_relay: optional callback(envelope: dict) -> (accepted: bool,
            reason: str), called for POST /relay — a request from another
            node asking THIS node to hold an envelope on behalf of a
            THIRD party (see core/network/relay.py). Distinct from
            on_message/POST /inbound, which is for envelopes addressed
            to this node itself: conflating the two would mean anyone
            could get their own messages stored in a stranger's regular
            chat history just by POSTing to /inbound with a mismatched
            chat_id. If omitted, POST /relay answers 404 — same as if
            this node doesn't support relaying at all.
        """
        self._host = host
        self._port = port
        self._on_message = on_message
        self._identity_provider = identity_provider
        self._on_relay = on_relay
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
        elif method == "POST" and path == "/relay":
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
                if length > _MAX_BODY_BYTES:
                    log.warning("[transport] relay rejected: body too large (%d bytes)", length)
                    resp = json.dumps({"error": "payload too large"}).encode()
                    start_response("413 Payload Too Large", [
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(resp))),
                    ])
                    return [resp]
                body     = environ["wsgi.input"].read(length)
                envelope = json.loads(body.decode("utf-8"))
                if self._on_relay is None:
                    status = "404 Not Found"
                    resp   = json.dumps({"error": "this node doesn't relay"}).encode()
                else:
                    accepted, reason = self._on_relay(envelope)
                    if accepted:
                        status = "200 OK"
                        resp   = b'{"ok": true}'
                    else:
                        status = "403 Forbidden"
                        resp   = json.dumps({"error": reason or "relay rejected"}).encode()
            except Exception as e:
                log.warning("[transport] relay error: %s", e)
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
        if not validate_peer_address(peer_address):
            log.warning("[transport] refusing send to invalid peer address %r", peer_address)
            return False
        url  = f"{peer_address.rstrip('/')}/inbound"
        body = json.dumps(envelope).encode("utf-8")
        req  = Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with _open(req, 5) as resp:
                log.debug("[transport] sent to %s -> %d", url, resp.status)
                return resp.status == 200
        except URLError as e:
            log.warning("[transport] send failed to %s: %s", url, e)
            return False

    def send_relay(self, relay_address: str, envelope: dict) -> bool:
        """
        Ask relay_address to hold envelope on behalf of whichever peer
        envelope["chat_id"] names (store-and-forward — see
        core/network/relay.py). Returns True only if the relay actually
        accepted it (200), not merely if the HTTP request itself
        succeeded — a relay can and does say no (not relaying, over
        capacity, etc.), which is a 403, not a delivery success.
        """
        if not validate_peer_address(relay_address):
            log.warning("[transport] refusing relay to invalid address %r", relay_address)
            return False
        url  = f"{relay_address.rstrip('/')}/relay"
        body = json.dumps(envelope).encode("utf-8")
        req  = Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with _open(req, 5) as resp:
                log.debug("[transport] relayed via %s -> %d", url, resp.status)
                return resp.status == 200
        except URLError as e:
            log.warning("[transport] relay send failed to %s: %s", url, e)
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
        if not validate_peer_address(peer_address):
            log.info("[transport] refusing identity fetch from invalid address %r", peer_address)
            return None
        url = f"{peer_address.rstrip('/')}/identity"
        try:
            with _open(Request(url), 5) as resp:
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
        if not validate_peer_address(peer_address):
            return False
        url = f"{peer_address.rstrip('/')}/health"
        req = Request(url)
        try:
            with _open(req, 3) as resp:
                return resp.status == 200
        except URLError:
            return False
