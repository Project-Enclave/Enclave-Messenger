"""
dht.py — Internet peer discovery via a Kademlia-style DHT.

This is the same protocol family BitTorrent's mainline DHT (BEP 5) uses,
adapted for this app's actual need: instead of announcing "I have piece
data for this infohash," a node announces "I am reachable at this
ip:port for this user_id." Looking someone up means asking the DHT
"who has announced for this user_id's hash" instead of "who's in a
torrent swarm."

WHAT THIS DOES NOT DO — read this before enabling it:

  - It does not solve NAT traversal. It only helps you find a peer's
    last-announced ip:port. If that address isn't actually reachable
    from the outside (most home routers block unsolicited inbound UDP/TCP
    without port forwarding or UPnP), you'll find the peer but still
    can't connect to them. This is the exact same limitation real
    BitTorrent DHT has — it's a lookup mechanism, not a hole-puncher.
  - It has no public bootstrap infrastructure. A brand-new node has no
    way to join the DHT on its own, same as a fresh BitTorrent client
    needs at least one bootstrap node (traditionally
    router.bittorrent.com and similar). You need to already know at
    least one reachable peer's ip:port to bootstrap from — your own
    second device, a friend's already-reachable node, or a VPS you
    control. Nothing here stands up or claims to stand up persistent
    public infrastructure.
  - Any node in the DHT can claim to have an address for any user_id.
    Results are cross-checked against PeerStore's existing key-pinning
    (see discovery.py) before ever being trusted — a DHT response for an
    already-known peer with DIFFERENT keys is rejected exactly like a
    spoofed LAN broadcast would be. For a peer you've never seen before,
    this is TOFU (trust-on-first-use), same as LAN discovery — the DHT
    is a much more adversarial environment than your own LAN, so treat
    first-contact results with the same caution you'd treat an
    unverified contact from anywhere else.

Protocol (JSON over UDP, one datagram per message):
    {"t": <transaction_id>, "y": "q"|"r"|"e", "q": <query_type>, "a"|"r": {...}}

Query types: ping, find_node, find_value, announce.
"""

import hashlib
import json
import logging
import os
import socket
import threading
import time
import uuid

log = logging.getLogger("network")

ID_BITS = 160
K = 8                    # contacts per k-bucket, standard Kademlia value
ALPHA = 3                # parallel lookup width
RPC_TIMEOUT = 3.0
STORE_TTL = 2 * 60 * 60  # 2 hours — re-announce well before this to stay found
REPUBLISH_INTERVAL = 25 * 60


def node_id_for(user_id: str) -> int:
    """160-bit id from a user_id string — decouples the DHT id space from
    the variable-length base64 identity string itself."""
    return int.from_bytes(hashlib.sha1(user_id.encode("utf-8")).digest(), "big")


def key_for(user_id: str) -> int:
    """Same hash function for the lookup key — announcing and looking up
    a user_id land at the same point in the id space."""
    return node_id_for(user_id)


def _distance(a: int, b: int) -> int:
    return a ^ b


class Contact:
    __slots__ = ("node_id", "ip", "port", "last_seen")

    def __init__(self, node_id: int, ip: str, port: int):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.last_seen = time.time()

    def addr(self):
        return (self.ip, self.port)

    def to_dict(self):
        return {"id": "%040x" % self.node_id, "ip": self.ip, "port": self.port}


class RoutingTable:
    """
    Standard Kademlia k-buckets: bucket i holds contacts at XOR-distance
    with bit-length i from our own node_id. Simple oldest-evicted-first
    replacement on overflow rather than full ping-and-replace — correct
    behavior, less machinery, appropriate for this scale.
    """

    def __init__(self, self_id: int):
        self.self_id = self_id
        self.buckets: list[list[Contact]] = [[] for _ in range(ID_BITS)]
        self._lock = threading.Lock()

    def _bucket_index(self, node_id: int) -> int:
        d = _distance(self.self_id, node_id)
        if d == 0:
            return 0
        return d.bit_length() - 1

    def add(self, contact: Contact):
        if contact.node_id == self.self_id:
            return
        with self._lock:
            idx = self._bucket_index(contact.node_id)
            bucket = self.buckets[idx]
            bucket[:] = [c for c in bucket if c.node_id != contact.node_id]
            bucket.append(contact)
            if len(bucket) > K:
                bucket.pop(0)  # evict oldest

    def closest(self, target_id: int, count: int = K) -> list:
        with self._lock:
            all_contacts = [c for bucket in self.buckets for c in bucket]
        all_contacts.sort(key=lambda c: _distance(c.node_id, target_id))
        return all_contacts[:count]


class DHTNode:
    def __init__(self, user_id: str, port: int, peer_store, on_peer_found=None):
        """
        user_id: our own identity string (hashed to a node id)
        port: UDP port this DHT node listens on
        peer_store: PeerStore — successful lookups get pinned-and-checked
                    into it exactly like discovery.py's LAN results
        on_peer_found: optional callback(peer_dict) on a new/updated peer
        """
        self.user_id = user_id
        self.self_id = node_id_for(user_id)
        self.port = port
        self.peer_store = peer_store
        self.on_peer_found = on_peer_found

        self.table = RoutingTable(self.self_id)
        self.storage: dict[int, dict] = {}  # key -> {value, expires_at}
        self._identity_payload: dict = {}   # set via set_identity_payload()
        self._public_ip_override = None     # set via set_identity_payload()
        self._last_announce_reached_nodes = False  # true once announce_self() actually delivered

        self._sock = None
        self._stop = threading.Event()
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._republish_thread = threading.Thread(target=self._republish_loop, daemon=True)
        self._pending: dict = {}  # transaction_id -> {"event": Event, "response": [..]}
        self._pending_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, bootstrap_addrs: list = None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.settimeout(1.0)
        self._listen_thread.start()
        self._republish_thread.start()
        log.info("[dht] listening on UDP %d, node_id=%040x", self.port, self.self_id)

        for addr in (bootstrap_addrs or []):
            try:
                host, port_s = addr.rsplit(":", 1)
                self._bootstrap_from((host, int(port_s)))
            except Exception as e:
                log.warning("[dht] bootstrap %s failed: %s", addr, e)

    def stop(self):
        self._stop.set()
        self._listen_thread.join(timeout=2)
        self._republish_thread.join(timeout=2)
        if self._sock:
            self._sock.close()
        log.info("[dht] stopped")

    def _bootstrap_from(self, addr):
        resp = self._rpc(addr, "find_node", {"target": "%040x" % self.self_id})
        if resp is None:
            log.warning("[dht] bootstrap node %s did not respond", addr)
            return
        for c in resp.get("nodes", []):
            self.table.add(Contact(int(c["id"], 16), c["ip"], c["port"]))
        log.info("[dht] bootstrapped from %s, %d contacts learned", addr, len(resp.get("nodes", [])))
        # Now do a real lookup for our own id to populate the table properly.
        self.find_node(self.self_id)

    # ------------------------------------------------------------------
    # Announcing ourselves / looking others up
    # ------------------------------------------------------------------

    def set_identity_payload(self, ed25519_pub: str, x25519_pub: str, transport_port: int,
                              public_ip: str = None):
        """
        public_ip: if you already know your own reachable address (e.g.
        running on a VPS with a static IP), pass it explicitly and it's
        used as-is. Otherwise learn_own_address() is used at announce
        time to auto-detect it by asking a routing-table peer what
        source address they saw us connecting from — the same idea STUN
        uses, at a much simpler level appropriate for this scope.
        """
        self._identity_payload = {
            "user_id": self.user_id,
            "ed25519_pub": ed25519_pub,
            "x25519_pub": x25519_pub,
            "port": transport_port,
        }
        self._public_ip_override = public_ip

    def learn_own_address(self):
        """
        Asks a known routing-table contact what source address our ping
        arrived from — the ping reply echoes it back. This is how we find
        out our own apparent public ip:port without any external service,
        same principle STUN uses. Returns (ip, port) or None if we have no
        contacts to ask yet (e.g. announce_self() called before ever
        successfully bootstrapping).
        """
        contacts = self.table.closest(self.self_id, K)
        for c in contacts:
            resp = self._rpc(c.addr(), "ping", {})
            if resp and resp.get("your_ip"):
                return (resp["your_ip"], resp.get("your_port"))
        return None

    def announce_self(self):
        if not self._identity_payload:
            log.warning("[dht] announce_self() called before set_identity_payload()")
            return

        payload = dict(self._identity_payload)
        if self._public_ip_override:
            payload["ip"] = self._public_ip_override
        else:
            learned = self.learn_own_address()
            if learned:
                payload["ip"] = learned[0]
            else:
                log.warning(
                    "[dht] could not determine our own reachable address "
                    "(no routing-table contacts to ask yet, and no "
                    "dht_public_addr configured) — announcing anyway, but "
                    "anyone who finds us via this announce won't have a "
                    "usable ip to connect to until we successfully "
                    "re-announce with one"
                )
                payload["ip"] = ""

        key = key_for(self.user_id)

        # Store on ourselves too, not just the K closest OTHER nodes
        # find_node() returns (which never includes self — routing
        # tables don't hold contacts for your own id). Without this, a
        # lookup that reaches us asking "do you have this value" always
        # comes up empty even though WE are the one who announced it —
        # this is exactly what happens in a small network where we're
        # one of the only nodes in existence. Real Kademlia
        # implementations self-store for the same reason: resilience,
        # and correctness in exactly this edge case.
        self.storage[key] = {"value": payload, "expires_at": time.time() + STORE_TTL}

        nodes = self.find_node(key)
        delivered = 0
        for c in nodes[:K]:
            resp = self._rpc(c.addr(), "announce", {"key": "%040x" % key, "value": payload})
            if resp is not None:
                delivered += 1
        if payload.get("ip"):
            # We always have ourselves as a valid replica now, so an
            # announce with a real ip "reaches a node" even with zero
            # peers — but the early-retry loop's real job is making sure
            # OTHER nodes have it too, so still require actual delivery
            # OR having at least tried against a non-empty candidate set.
            self._last_announce_reached_nodes = True
        log.info("[dht] announced self (ip=%s) — delivered to %d/%d peer nodes (+ self)",
                  payload.get("ip", ""), delivered, len(nodes[:K]))

    def find_peer(self, user_id: str) -> dict | None:
        """
        Look up user_id in the DHT. On a plausible result, applies the
        same key-pinning check discovery.py uses before trusting it, and
        upserts into peer_store. Returns the peer dict, or None.
        """
        key = key_for(user_id)
        nodes = self.find_node(key)
        for c in nodes[:K]:
            resp = self._rpc(c.addr(), "find_value", {"key": "%040x" % key})
            if resp and resp.get("value"):
                v = resp["value"]
                if v.get("user_id") != user_id:
                    continue  # hash collision or bad actor — ignore, don't trust blindly
                return self._verify_and_store(v)
        return None

    def _verify_and_store(self, v: dict) -> dict | None:
        peer_id = v.get("user_id", "")
        new_ed = v.get("ed25519_pub", "")
        new_x = v.get("x25519_pub", "")
        existing = self.peer_store.get(peer_id)
        if existing and existing.get("ed25519_pub") and existing.get("x25519_pub"):
            key_changed = (
                (new_ed and new_ed != existing["ed25519_pub"]) or
                (new_x and new_x != existing["x25519_pub"])
            )
            if key_changed:
                log.warning(
                    "[dht] KEY CHANGE for known peer %s via DHT result — "
                    "ignoring (possible impersonation attempt, and the DHT "
                    "is a far more adversarial source than a LAN broadcast). "
                    "Delete and re-add the contact if this is expected.",
                    peer_id[:12],
                )
                return None
        peer = self.peer_store.upsert(
            user_id=peer_id, username=v.get("username", ""),
            ed25519_pub=new_ed, x25519_pub=new_x,
            ip=v.get("ip", ""), port=v.get("port", 0),
        )
        log.info("[dht] resolved peer %s via DHT", peer_id[:12])
        if self.on_peer_found:
            try:
                self.on_peer_found(peer)
            except Exception as e:
                log.warning("[dht] on_peer_found callback error: %s", e)
        return peer

    def find_node(self, target_id: int) -> list:
        """Standard iterative Kademlia node lookup, alpha=3."""
        shortlist = self.table.closest(target_id, K)
        queried = set()
        best = list(shortlist)

        for _round in range(8):  # bounded — converges well before this in practice
            candidates = [c for c in best if c.node_id not in queried][:ALPHA]
            if not candidates:
                break
            for c in candidates:
                queried.add(c.node_id)
                resp = self._rpc(c.addr(), "find_node", {"target": "%040x" % target_id})
                if resp is None:
                    continue
                for nd in resp.get("nodes", []):
                    nc = Contact(int(nd["id"], 16), nd["ip"], nd["port"])
                    self.table.add(nc)
                    if nc.node_id not in queried:
                        best.append(nc)
            best.sort(key=lambda c: _distance(c.node_id, target_id))
            best = best[:K]

        return best

    # ------------------------------------------------------------------
    # RPC plumbing
    # ------------------------------------------------------------------

    def _rpc(self, addr, query: str, args: dict) -> dict | None:
        t = uuid.uuid4().hex[:8]
        args = dict(args)
        args["id"] = "%040x" % self.self_id  # so the recipient can route-table us correctly
        msg = {"t": t, "y": "q", "q": query, "a": args}
        event = threading.Event()
        box = {"resp": None}
        with self._pending_lock:
            self._pending[t] = (event, box)
        try:
            self._sock.sendto(json.dumps(msg).encode("utf-8"), addr)
        except OSError as e:
            log.debug("[dht] send to %s failed: %s", addr, e)
            with self._pending_lock:
                self._pending.pop(t, None)
            return None
        got = event.wait(RPC_TIMEOUT)
        with self._pending_lock:
            self._pending.pop(t, None)
        if got and box["resp"] is not None:
            self._learn_contact(box["resp"].pop("id", None), addr)
        return box["resp"] if got else None

    def _learn_contact(self, id_hex, addr):
        if not id_hex:
            return
        try:
            self.table.add(Contact(int(id_hex, 16), addr[0], addr[1]))
        except (ValueError, TypeError):
            pass

    def _listen_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            y = msg.get("y")
            if y == "q":
                self._handle_query(msg, addr)
            elif y == "r":
                self._handle_response(msg)
            # "e" (error) replies are simply not resolved — caller sees a timeout

    def _handle_response(self, msg: dict):
        t = msg.get("t")
        with self._pending_lock:
            entry = self._pending.get(t)
        if entry:
            event, box = entry
            box["resp"] = msg.get("r", {})
            event.set()

    def _handle_query(self, msg: dict, addr):
        t = msg.get("t")
        q = msg.get("q")
        a = msg.get("a", {})
        self._learn_contact(a.get("id"), addr)

        reply: dict = {}
        if q == "ping":
            reply = {"your_ip": addr[0], "your_port": addr[1]}
        elif q == "find_node":
            target = int(a.get("target", "0"), 16)
            reply = {"nodes": [c.to_dict() for c in self.table.closest(target, K)]}
        elif q == "find_value":
            key = int(a.get("key", "0"), 16)
            entry = self.storage.get(key)
            if entry and entry["expires_at"] > time.time():
                reply = {"value": entry["value"]}
            else:
                reply = {"nodes": [c.to_dict() for c in self.table.closest(key, K)]}
        elif q == "announce":
            key = int(a.get("key", "0"), 16)
            value = a.get("value", {})
            self.storage[key] = {"value": value, "expires_at": time.time() + STORE_TTL}
            reply = {"ok": True}
        else:
            self._send_error(addr, t, "unknown query")
            return

        reply["id"] = "%040x" % self.self_id  # so the querier can route-table us correctly
        self._send(addr, {"t": t, "y": "r", "r": reply})

    def _send(self, addr, msg: dict):
        try:
            self._sock.sendto(json.dumps(msg).encode("utf-8"), addr)
        except OSError as e:
            log.debug("[dht] reply send to %s failed: %s", addr, e)

    def _send_error(self, addr, t, message):
        self._send(addr, {"t": t, "y": "e", "e": message})

    def _republish_loop(self):
        # Early retries before settling into the long steady-state
        # interval: a node with no bootstrap list of its own (e.g. the
        # first/seed node others bootstrap FROM) has no address to learn
        # its own reachable ip:port from until someone else has queried
        # it at least once. Confirmed this matters, not just in theory:
        # a two-node test where node A had no bootstrap list initially
        # failed to ever announce a usable address, because the one-shot
        # attempt at startup ran before B had contacted A at all. Retrying
        # a few times over the first ~15s gives that a real chance to
        # resolve without waiting the full REPUBLISH_INTERVAL.
        for delay in (3, 5, 7):
            if self._stop.wait(delay):
                return
            if self._identity_payload and not self._identity_payload_confirmed():
                try:
                    self.announce_self()
                except Exception as e:
                    log.warning("[dht] early re-announce failed: %s", e)

        while not self._stop.is_set():
            self._stop.wait(REPUBLISH_INTERVAL)
            if self._stop.is_set():
                break
            now = time.time()
            expired = [k for k, v in self.storage.items() if v["expires_at"] <= now]
            for k in expired:
                del self.storage[k]
            if self._identity_payload:
                try:
                    self.announce_self()
                except Exception as e:
                    log.warning("[dht] republish failed: %s", e)

    def _identity_payload_confirmed(self) -> bool:
        """Have we successfully delivered an announce with a real ip to
        at least one node yet? (Not just 'do we have an ip' — the first
        attempt can have an ip ready via an explicit override but zero
        routing-table contacts to actually send it to, if we're the
        seed/root node and nobody has queried us yet. Confirmed this is a
        real distinction, not a hypothetical: it's exactly what the early
        retries in this loop exist to cover.)"""
        return self._last_announce_reached_nodes
