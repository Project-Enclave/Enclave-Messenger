"""
discovery.py — LAN peer discovery via UDP multicast.

Protocol:
  Every ANNOUNCE_INTERVAL seconds, each node sends a JSON datagram to the
  multicast group MCAST_GRP:DISCOVERY_PORT.

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

  This uses multicast, not broadcast, specifically so that MULTIPLE
  Enclave profiles running as separate processes on the SAME machine each
  reliably see each other's announcements. Plain UDP broadcast plus
  SO_REUSEPORT does NOT do that: on Linux, SO_REUSEPORT load-balances
  incoming datagrams across the sockets sharing a port — the kernel
  delivers each packet to exactly ONE of them, not a copy to each. Two
  local profiles both listening via SO_REUSEPORT on a broadcast port each
  only received roughly half of all announcements, non-deterministically,
  and in three independent trials it was essentially always "exactly one
  side sees the other," never both. Confirmed this directly before
  switching to multicast: joining a multicast group instead genuinely
  fans a single sent packet out to every joined socket on the host
  (verified with two simultaneous local receivers both getting the same
  packet), which is the actual delivery semantics this needs.
"""

import json
import socket
import struct
import threading
import time
import logging

DISCOVERY_PORT = 51820
MCAST_GRP = "239.255.42.99"  # organization-local scope (239.0.0.0/8) — not a
                              # well-known protocol's address, so it won't
                              # collide with real mDNS/SSDP/etc. traffic
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
        # Wait for both threads to finish so sockets close cleanly.
        self._announce_thread.join(timeout=2)
        self._listen_thread.join(timeout=2)

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
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(1.0)

        def _send_once():
            try:
                sock.sendto(self._build_datagram(), (MCAST_GRP, DISCOVERY_PORT))
                log.debug("[discovery] announced presence")
            except OSError as e:
                log.warning("[discovery] announce error: %s", e)

        # Send immediately, then once more after a short grace period, before
        # settling into the steady-state ANNOUNCE_INTERVAL cadence. Two
        # freshly-started nodes both joining the multicast group at startup
        # have a real (if small) race: an announce sent before the other
        # side's IP_ADD_MEMBERSHIP has completed is simply never delivered
        # to it — multicast doesn't buffer for late joiners — and without
        # this second early send, that means waiting up to a full
        # ANNOUNCE_INTERVAL (30s) for the next one. Confirmed this race is
        # real by testing two local instances directly: a 6s window sending
        # only the single immediate announce showed exactly one side
        # discovering the other, never both, never neither, across four
        # trials — but both sides converged correctly once a second cycle
        # had time to run. This closes that gap without changing the
        # steady-state broadcast rate at all.
        _send_once()
        self._stop.wait(2.0)
        if not self._stop.is_set():
            _send_once()

        while not self._stop.is_set():
            self._stop.wait(ANNOUNCE_INTERVAL)
            if not self._stop.is_set():
                _send_once()
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
        sock.bind(("", DISCOVERY_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
        log.info("[discovery] listening on multicast %s:%d", MCAST_GRP, DISCOVERY_PORT)
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

        new_ed = msg.get("ed25519_pub", "")
        new_x  = msg.get("x25519_pub", "")

        # Key pinning (TOFU): once we've recorded keys for a user_id, a later
        # broadcast claiming the SAME user_id with DIFFERENT keys is either
        # the peer legitimately regenerating their identity, or someone on
        # the network trying to hijack that contact's key mapping so future
        # messages get encrypted to them instead. We can't tell those apart
        # automatically, so we refuse to silently overwrite — update address
        # only, keep the pinned keys, and log loudly. A real UI would surface
        # this as "peer identity changed — re-verify" instead of auto-trusting.
        existing = self._peer_store.get(peer_id)
        if existing and existing.get("ed25519_pub") and existing.get("x25519_pub"):
            key_changed = (
                (new_ed and new_ed != existing["ed25519_pub"]) or
                (new_x and new_x != existing["x25519_pub"])
            )
            if key_changed:
                log.warning(
                    "[discovery] KEY CHANGE for known peer %s @ %s — "
                    "ignoring entire broadcast, including address "
                    "(possible impersonation/MITM attempt). Delete and "
                    "re-add the contact if this is expected.",
                    peer_id[:12], src_ip,
                )
                # Deliberately do NOT call update_address here either.
                # Trusting the new IP while keeping the old key still lets
                # an attacker redirect/deny delivery even without being able
                # to read plaintext. If we can't trust the identity claim,
                # we can't trust anything else in the same broadcast.
                return

        peer = self._peer_store.upsert(
            user_id=peer_id,
            username=msg.get("username", ""),
            ed25519_pub=new_ed,
            x25519_pub=new_x,
            ip=src_ip,
            port=msg.get("port", 0),
        )
        log.info("[discovery] saw peer %s @ %s", peer_id[:12], src_ip)

        if self._on_peer_found:
            try:
                self._on_peer_found(peer)
            except Exception as e:
                log.warning("[discovery] on_peer_found callback error: %s", e)
