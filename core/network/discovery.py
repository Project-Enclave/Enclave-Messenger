"""
discovery.py — LAN peer discovery via UDP broadcast.

Protocol:
  Every ANNOUNCE_INTERVAL seconds, each node broadcasts a JSON datagram
  on UDP port DISCOVERY_PORT to the subnet broadcast address (255.255.255.255).

  Datagram format:
    {
      "enclave": 1,
      "user_id":    str,
      "username":   str,
      "ed25519_pub": str,
      "x25519_pub":  str,
      "port":       int   <- transport HTTP port
    }

  On receiving a datagram from a different user_id, the node upserts the
  sender into PeerStore with their current IP (from the UDP source address).
"""

import json
import socket
import threading
import time
import logging

DISCOVERY_PORT = 51820
ANNOUNCE_INTERVAL = 30  # seconds
BUFSIZ = 4096

log = logging.getLogger("network")


class Discovery:
    def __init__(self, identity: dict, transport_port: int, peer_store, on_peer_found=None):
        """
        identity: {
          "user_id": str,
          "username": str,
          "ed25519_pub": str,
          "x25519_pub": str,
        }
        transport_port: the HTTP port peers should connect to
        peer_store: PeerStore instance
        on_peer_found: optional callback(peer_dict) when a new peer is seen
        """
        self._identity = identity
        self._transport_port = transport_port
        self._peer_store = peer_store
        self._on_peer_found = on_peer_found
        self._stop = threading.Event()
        self._announce_thread = threading.Thread(target=self._announce_loop, daemon=True)
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)

    def start(self):
        log.info("[discovery] starting — port %d", DISCOVERY_PORT)
        self._listen_thread.start()
        self._announce_thread.start()

    def stop(self):
        self._stop.set()

    # ------------------------------------------------------------------
    # Announce
    # ------------------------------------------------------------------

    def _build_datagram(self) -> bytes:
        payload = {
            "enclave": 1,
            "user_id":    self._identity["user_id"],
            "username":   self._identity["username"],
            "ed25519_pub": self._identity["ed25519_pub"],
            "x25519_pub":  self._identity["x25519_pub"],
            "port":        self._transport_port,
        }
        return json.dumps(payload).encode("utf-8")

    def _announce_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                # Rebuild each iteration so runtime identity changes
                # (e.g. username update) are always reflected.
                data = self._build_datagram()
                sock.sendto(data, ("255.255.255.255", DISCOVERY_PORT))
                log.debug("[discovery] announced presence")
            except OSError as e:
                log.warning("[discovery] announce error: %s", e)
            self._stop.wait(ANNOUNCE_INTERVAL)
        sock.close()

    # ------------------------------------------------------------------
    # Listen
    # ------------------------------------------------------------------

    def _listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Windows doesn't have SO_REUSEPORT
        sock.bind(("0.0.0.0", DISCOVERY_PORT))
        sock.settimeout(1.0)
        log.info("[discovery] listening on UDP %d", DISCOVERY_PORT)
        while not self._stop.is_set():
            try:
                data, (src_ip, _) = sock.recvfrom(BUFSIZ)
            except socket.timeout:
                continue
            except OSError as e:
                log.warning("[discovery] recv error: %s", e)
                continue
            self._handle(data, src_ip)
        sock.close()

    def _handle(self, data: bytes, src_ip: str):
        try:
            msg = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if msg.get("enclave") != 1:
            return

        peer_id = msg.get("user_id", "")
        if not peer_id or peer_id == self._identity["user_id"]:
            return  # ignore our own broadcasts

        peer = self._peer_store.upsert(
            user_id=peer_id,
            username=msg.get("username", ""),
            ed25519_pub=msg.get("ed25519_pub", ""),
            x25519_pub=msg.get("x25519_pub", ""),
            ip=src_ip,
            port=msg.get("port", 0),
        )
        log.info("[discovery] saw peer %s @ %s", peer_id[:12], src_ip)

        if self._on_peer_found:
            try:
                self._on_peer_found(peer)
            except Exception as e:
                log.warning("[discovery] on_peer_found callback error: %s", e)
