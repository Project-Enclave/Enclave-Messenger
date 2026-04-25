# core/dht.py
# kademlia-based DHT node for enclave messenger
# handles peer discovery without any central server
# --------------------------------------------------
# dependencies: pip install cryptography (already have it)
# uses python asyncio + udp sockets

import asyncio
import hashlib
import json
import os
import time
import struct
from typing import Optional


# ── constants ──────────────────────────────────────────────────

K          = 20      # k-bucket size (how many peers per bucket). bittorrent uses 20.
ALPHA      = 3       # concurrency: how many parallel lookups at once
ID_BITS    = 160     # keyspace size in bits
TTL        = 3600    # how long a stored value lives (seconds)
TIMEOUT    = 5.0     # rpc timeout in seconds


# ── node id ────────────────────────────────────────────────────

class NodeID:
    """
    a 160-bit identifier for a node or a value in the DHT.
    distance between two nodes = XOR of their IDs.
    that's the core of kademlia — closer = smaller XOR.
    """

    def __init__(self, raw: bytes):
        assert len(raw) == 20, "node id must be 20 bytes (160 bits)"
        self.raw = raw

    @classmethod
    def random(cls) -> "NodeID":
        return cls(os.urandom(20))

    @classmethod
    def from_key(cls, key: str) -> "NodeID":
        """derive a deterministic node id from any string (e.g. user_id)"""
        return cls(hashlib.sha1(key.encode()).digest())

    def distance(self, other: "NodeID") -> int:
        """XOR distance. smaller = closer in the kademlia sense."""
        a = int.from_bytes(self.raw, "big")
        b = int.from_bytes(other.raw, "big")
        return a ^ b

    def bucket_index(self, other: "NodeID") -> int:
        """which k-bucket does 'other' belong in, from our perspective"""
        d = self.distance(other)
        if d == 0:
            return 0
        return d.bit_length() - 1

    def hex(self) -> str:
        return self.raw.hex()

    def __eq__(self, other):
        return isinstance(other, NodeID) and self.raw == other.raw

    def __hash__(self):
        return hash(self.raw)

    def __repr__(self):
        return f"NodeID({self.raw.hex()[:12]}...)"


# ── peer ───────────────────────────────────────────────────────

class Peer:
    """a peer we know about in the network"""

    def __init__(self, node_id: NodeID, ip: str, port: int):
        self.node_id   = node_id
        self.ip        = ip
        self.port      = port
        self.last_seen = time.time()

    @property
    def address(self) -> tuple:
        return (self.ip, self.port)

    def seen(self):
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id.hex(),
            "ip":      self.ip,
            "port":    self.port,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Peer":
        return cls(NodeID(bytes.fromhex(d["node_id"])), d["ip"], d["port"])

    def __repr__(self):
        return f"Peer({self.node_id.raw.hex()[:8]}... @ {self.ip}:{self.port})"


# ── k-bucket ───────────────────────────────────────────────────

class KBucket:
    """
    stores up to K peers at a specific distance range from us.
    kademlia routing table = 160 of these buckets.
    least-recently-seen peer is at index 0.
    """

    def __init__(self):
        self.peers: list[Peer] = []

    def add(self, peer: Peer) -> bool:
        """
        returns True if added/updated, False if bucket full and head is alive.
        if full and head is dead, evict head and add new peer.
        """
        # already know this peer? just update last_seen
        for p in self.peers:
            if p.node_id == peer.node_id:
                self.peers.remove(p)
                self.peers.append(peer)
                peer.seen()
                return True

        if len(self.peers) < K:
            self.peers.append(peer)
            return True

        # bucket full — kademlia says: ping the oldest peer first
        # if it's alive, drop the new one. if dead, evict and add new.
        # for now we just evict the oldest (TODO: add actual ping check)
        self.peers.pop(0)
        self.peers.append(peer)
        return True

    def get_closest(self, count: int) -> list[Peer]:
        return list(self.peers[-count:])

    def __len__(self):
        return len(self.peers)


# ── routing table ──────────────────────────────────────────────

class RoutingTable:
    """
    160 k-buckets. one per bit of the keyspace.
    finding the right bucket = find the bit length of XOR distance.
    """

    def __init__(self, own_id: NodeID):
        self.own_id  = own_id
        self.buckets = [KBucket() for _ in range(ID_BITS)]

    def add(self, peer: Peer):
        if peer.node_id == self.own_id:
            return  # don't add ourselves
        idx = self.own_id.bucket_index(peer.node_id)
        self.buckets[idx].add(peer)

    def find_closest(self, target: NodeID, count: int = K) -> list[Peer]:
        """find the `count` closest peers we know to a target node id"""
        all_peers = []
        for bucket in self.buckets:
            all_peers.extend(bucket.peers)
        all_peers.sort(key=lambda p: p.node_id.distance(target))
        return all_peers[:count]

    def get_peer(self, node_id: NodeID) -> Optional[Peer]:
        idx = self.own_id.bucket_index(node_id)
        for p in self.buckets[idx].peers:
            if p.node_id == node_id:
                return p
        return None

    def total_peers(self) -> int:
        return sum(len(b) for b in self.buckets)


# ── message types ──────────────────────────────────────────────
# all dht messages are json over udp
# keeping it simple and debuggable

MSG_PING         = "ping"
MSG_PONG         = "pong"
MSG_FIND_NODE    = "find_node"
MSG_FIND_NODE_R  = "find_node_r"
MSG_STORE        = "store"
MSG_STORE_R      = "store_r"
MSG_FIND_VALUE   = "find_value"
MSG_FIND_VALUE_R = "find_value_r"


def make_msg(type_: str, sender: Peer, **kwargs) -> bytes:
    msg = {"type": type_, "sender": sender.to_dict(), **kwargs}
    return json.dumps(msg).encode()

def parse_msg(data: bytes) -> dict:
    return json.loads(data.decode())


# ── dht node ───────────────────────────────────────────────────

class DHTNode:
    """
    the main kademlia node.
    - finds other enclave peers on the internet
    - stores and retrieves identity bundles by user_id
    - no central server needed
    """

    def __init__(self, ip: str, port: int, node_id: NodeID = None):
        self.ip        = ip
        self.port      = port
        self.node_id   = node_id or NodeID.random()
        self.me        = Peer(self.node_id, ip, port)
        self.routing   = RoutingTable(self.node_id)
        self.store: dict[str, tuple[dict, float]] = {}  # key → (value, expires_at)
        self._transport = None
        self._protocol  = None
        self._pending: dict[str, asyncio.Future] = {}   # rpc id → future

    # ── startup ──

    async def start(self):
        loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self),
            local_addr=(self.ip, self.port)
        )
        print(f"[dht] node started on {self.ip}:{self.port}")
        print(f"[dht] node id: {self.node_id.hex()[:20]}...")

    async def stop(self):
        if self._transport:
            self._transport.close()

    # ── bootstrap ──

    async def bootstrap(self, bootstrap_peers: list[tuple[str, int]]):
        """
        connect to known bootstrap peers to join the network.
        bootstrap peers are just hardcoded well-known nodes.
        after this, we find our own neighbours through normal lookups.
        """
        print(f"[dht] bootstrapping with {len(bootstrap_peers)} peers...")
        for ip, port in bootstrap_peers:
            # we don't know their node id yet, use a placeholder
            temp_id = NodeID.from_key(f"{ip}:{port}")
            peer    = Peer(temp_id, ip, port)
            await self.ping(peer)

        # find our own node id in the network to fill routing table
        await self.find_node(self.node_id)
        print(f"[dht] bootstrap done. know {self.routing.total_peers()} peers.")

    # ── core rpcs ──

    async def ping(self, peer: Peer) -> bool:
        """check if a peer is alive"""
        rpc_id = os.urandom(4).hex()
        msg    = make_msg(MSG_PING, self.me, rpc_id=rpc_id)
        try:
            resp = await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
            if resp and resp.get("type") == MSG_PONG:
                # update routing table with confirmed-alive peer
                real_id = NodeID(bytes.fromhex(resp["sender"]["node_id"]))
                peer.node_id = real_id
                self.routing.add(peer)
                return True
        except asyncio.TimeoutError:
            pass
        return False

    async def find_node(self, target: NodeID) -> list[Peer]:
        """
        iterative node lookup. asks the closest peers we know for closer peers.
        stops when we can't get any closer.
        """
        closest = self.routing.find_closest(target, ALPHA)
        if not closest:
            return []

        asked   = set()
        results = list(closest)

        while True:
            to_ask = [p for p in results if p.node_id.hex() not in asked][:ALPHA]
            if not to_ask:
                break

            futures = [self._rpc_find_node(p, target) for p in to_ask]
            for p in to_ask:
                asked.add(p.node_id.hex())

            responses = await asyncio.gather(*futures, return_exceptions=True)

            new_found = False
            for resp in responses:
                if isinstance(resp, list):
                    for peer_dict in resp:
                        peer = Peer.from_dict(peer_dict)
                        if peer.node_id not in [r.node_id for r in results]:
                            results.append(peer)
                            self.routing.add(peer)
                            new_found = True

            if not new_found:
                break

            results.sort(key=lambda p: p.node_id.distance(target))
            results = results[:K]

        return results

    async def store_value(self, key: str, value: dict):
        """
        store a value (e.g. an identity bundle) on the K closest nodes.
        key is typically a user_id.
        """
        target   = NodeID.from_key(key)
        closest  = await self.find_node(target)
        futures  = [self._rpc_store(p, key, value) for p in closest[:K]]
        await asyncio.gather(*futures, return_exceptions=True)
        print(f"[dht] stored '{key[:20]}...' on {len(closest)} nodes")

    async def get_value(self, key: str) -> Optional[dict]:
        """
        find a value by key. returns the value dict or None if not found.
        this is how you look up someone's identity bundle by their user_id.
        """
        target  = NodeID.from_key(key)
        closest = self.routing.find_closest(target, ALPHA)
        asked   = set()

        while True:
            to_ask = [p for p in closest if p.node_id.hex() not in asked][:ALPHA]
            if not to_ask:
                break
            futures = [self._rpc_find_value(p, key) for p in to_ask]
            for p in to_ask:
                asked.add(p.node_id.hex())
            responses = await asyncio.gather(*futures, return_exceptions=True)
            for resp in responses:
                if isinstance(resp, dict) and resp.get("found"):
                    return resp["value"]
                elif isinstance(resp, list):
                    for peer_dict in resp:
                        peer = Peer.from_dict(peer_dict)
                        if peer.node_id not in [c.node_id for c in closest]:
                            closest.append(peer)

        # check local store too
        if key in self.store:
            val, expires = self.store[key]
            if time.time() < expires:
                return val
        return None

    # ── announce yourself ──

    async def announce(self, identity_bundle: dict):
        """
        tell the network "i'm here, this is my identity bundle."
        call this on startup and periodically (e.g. every 30 min).
        """
        user_id = identity_bundle.get("user_id")
        if not user_id:
            raise ValueError("identity bundle must have a user_id")
        await self.store_value(user_id, identity_bundle)
        print(f"[dht] announced as {user_id[:24]}...")

    async def find_user(self, user_id: str) -> Optional[dict]:
        """look up a contact's identity bundle by their user_id"""
        result = await self.get_value(user_id)
        if result:
            print(f"[dht] found user {user_id[:24]}...")
        else:
            print(f"[dht] user {user_id[:24]}... not found")
        return result

    # ── internal rpc helpers ──

    async def _rpc_find_node(self, peer: Peer, target: NodeID):
        rpc_id = os.urandom(4).hex()
        msg    = make_msg(MSG_FIND_NODE, self.me, rpc_id=rpc_id, target=target.hex())
        try:
            resp = await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
            if resp:
                return resp.get("peers", [])
        except asyncio.TimeoutError:
            pass
        return []

    async def _rpc_store(self, peer: Peer, key: str, value: dict):
        rpc_id = os.urandom(4).hex()
        msg    = make_msg(MSG_STORE, self.me, rpc_id=rpc_id, key=key, value=value)
        try:
            await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
        except asyncio.TimeoutError:
            pass

    async def _rpc_find_value(self, peer: Peer, key: str):
        rpc_id = os.urandom(4).hex()
        msg    = make_msg(MSG_FIND_VALUE, self.me, rpc_id=rpc_id, key=key)
        try:
            resp = await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
            return resp
        except asyncio.TimeoutError:
            pass
        return None

    async def _send_recv(self, addr: tuple, msg: bytes, rpc_id: str, timeout: float) -> Optional[dict]:
        loop   = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending[rpc_id] = future
        self._transport.sendto(msg, addr)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(rpc_id, None)

    # ── incoming message handler ──

    def _handle_message(self, data: bytes, addr: tuple):
        try:
            msg    = parse_msg(data)
            mtype  = msg.get("type")
            rpc_id = msg.get("rpc_id")
            sender = Peer.from_dict(msg["sender"])
            self.routing.add(sender)

            # responses to our pending rpcs
            if rpc_id and rpc_id in self._pending:
                future = self._pending[rpc_id]
                if not future.done():
                    future.set_result(msg)
                return

            # incoming requests
            if mtype == MSG_PING:
                resp = make_msg(MSG_PONG, self.me, rpc_id=rpc_id)
                self._transport.sendto(resp, addr)

            elif mtype == MSG_FIND_NODE:
                target  = NodeID(bytes.fromhex(msg["target"]))
                closest = self.routing.find_closest(target, K)
                resp    = make_msg(MSG_FIND_NODE_R, self.me,
                                   rpc_id=rpc_id,
                                   peers=[p.to_dict() for p in closest])
                self._transport.sendto(resp, addr)

            elif mtype == MSG_STORE:
                key   = msg["key"]
                value = msg["value"]
                self.store[key] = (value, time.time() + TTL)
                resp  = make_msg(MSG_STORE_R, self.me, rpc_id=rpc_id, ok=True)
                self._transport.sendto(resp, addr)

            elif mtype == MSG_FIND_VALUE:
                key = msg["key"]
                if key in self.store:
                    val, expires = self.store[key]
                    if time.time() < expires:
                        resp = make_msg(MSG_FIND_VALUE_R, self.me,
                                        rpc_id=rpc_id, found=True, value=val)
                        self._transport.sendto(resp, addr)
                        return
                # not found here, return closest nodes instead
                target  = NodeID.from_key(key)
                closest = self.routing.find_closest(target, K)
                resp    = make_msg(MSG_FIND_VALUE_R, self.me,
                                   rpc_id=rpc_id, found=False,
                                   peers=[p.to_dict() for p in closest])
                self._transport.sendto(resp, addr)

        except Exception as e:
            print(f"[dht] error handling message: {e}")


# ── udp protocol ───────────────────────────────────────────────

class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: DHTNode):
        self.node = node

    def connection_made(self, transport):
        pass

    def datagram_received(self, data: bytes, addr: tuple):
        self.node._handle_message(data, addr)

    def error_received(self, exc):
        print(f"[dht] udp error: {exc}")


# ── quick demo ─────────────────────────────────────────────────

async def _demo():
    # spin up two local nodes and have them find each other
    node_a = DHTNode("127.0.0.1", 9000)
    node_b = DHTNode("127.0.0.1", 9001)

    await node_a.start()
    await node_b.start()

    print("\n── node a bootstraps from node b ──")
    await node_b.bootstrap([("127.0.0.1", 9000)])

    print("\n── node a stores a fake identity bundle ──")
    fake_bundle = {
        "user_id": "enc1_aabbccdd1122334455",
        "sign_pub": os.urandom(32).hex(),
        "device_label": "alice-desktop",
    }
    await node_a.store_value(fake_bundle["user_id"], fake_bundle)

    print("\n── node b looks up alice ──")
    await asyncio.sleep(0.2)
    result = await node_b.get_value(fake_bundle["user_id"])
    print(f"found: {result is not None}")
    if result:
        print(f"device label: {result.get('device_label')}")

    await node_a.stop()
    await node_b.stop()


if __name__ == "__main__":
    asyncio.run(_demo())
