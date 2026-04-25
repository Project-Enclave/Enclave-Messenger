# core/dht.py
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import time
from typing import Optional


# ── constants ──────────────────────────────────────────────────

K         = 20
ALPHA     = 3
ID_BITS   = 160
TTL       = 3600
TIMEOUT   = 5.0

LAN_DISCOVERY_PORT    = 9877          # separate UDP port for LAN broadcast
LAN_DISCOVERY_MAGIC   = b"enclave-discover-v1"
LAN_DISCOVERY_INTERVAL = 30          # seconds between broadcasts


# ── node id ────────────────────────────────────────────────────

class NodeID:
    def __init__(self, raw: bytes):
        assert len(raw) == 20
        self.raw = raw

    @classmethod
    def random(cls) -> "NodeID":
        return cls(os.urandom(20))

    @classmethod
    def from_key(cls, key: str) -> "NodeID":
        return cls(hashlib.sha1(key.encode()).digest())

    def distance(self, other: "NodeID") -> int:
        return int.from_bytes(self.raw, "big") ^ int.from_bytes(other.raw, "big")

    def bucket_index(self, other: "NodeID") -> int:
        d = self.distance(other)
        return 0 if d == 0 else d.bit_length() - 1

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
    def __init__(self, node_id: NodeID, ip: str, port: int):
        self.node_id   = node_id
        self.ip        = ip
        self.port      = port
        self.last_seen = time.time()

    @property
    def address(self):
        return (self.ip, self.port)

    def seen(self):
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {"node_id": self.node_id.hex(), "ip": self.ip, "port": self.port}

    @classmethod
    def from_dict(cls, d: dict) -> "Peer":
        return cls(NodeID(bytes.fromhex(d["node_id"])), d["ip"], d["port"])

    def __repr__(self):
        return f"Peer({self.node_id.raw.hex()[:8]}... @ {self.ip}:{self.port})"


# ── k-bucket ───────────────────────────────────────────────────

class KBucket:
    def __init__(self):
        self.peers: list[Peer] = []

    def add(self, peer: Peer) -> bool:
        for p in self.peers:
            if p.node_id == peer.node_id:
                self.peers.remove(p)
                self.peers.append(peer)
                peer.seen()
                return True
        if len(self.peers) < K:
            self.peers.append(peer)
            return True
        self.peers.pop(0)
        self.peers.append(peer)
        return True

    def get_closest(self, count: int) -> list[Peer]:
        return list(self.peers[-count:])

    def __len__(self):
        return len(self.peers)


# ── routing table ──────────────────────────────────────────────

class RoutingTable:
    def __init__(self, own_id: NodeID):
        self.own_id  = own_id
        self.buckets = [KBucket() for _ in range(ID_BITS)]

    def add(self, peer: Peer):
        if peer.node_id == self.own_id:
            return
        self.buckets[self.own_id.bucket_index(peer.node_id)].add(peer)

    def find_closest(self, target: NodeID, count: int = K) -> list[Peer]:
        all_peers = [p for b in self.buckets for p in b.peers]
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

MSG_PING         = "ping"
MSG_PONG         = "pong"
MSG_FIND_NODE    = "find_node"
MSG_FIND_NODE_R  = "find_node_r"
MSG_STORE        = "store"
MSG_STORE_R      = "store_r"
MSG_FIND_VALUE   = "find_value"
MSG_FIND_VALUE_R = "find_value_r"


def make_msg(type_: str, sender: Peer, **kwargs) -> bytes:
    return json.dumps({"type": type_, "sender": sender.to_dict(), **kwargs}).encode()

def parse_msg(data: bytes) -> dict:
    return json.loads(data.decode())


# ── lan discovery ──────────────────────────────────────────────

class LanDiscovery:
    """
    UDP broadcast-based LAN peer discovery.
    sends a broadcast every LAN_DISCOVERY_INTERVAL seconds.
    any enclave node on the same network hears it and replies
    with their DHT address — no hardcoded IPs needed.
    """

    def __init__(self, dht_node: "DHTNode", dht_port: int):
        self.dht        = dht_node
        self.dht_port   = dht_port
        self._sock      = None
        self._running   = False
        self._transport = None

    async def start(self):
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _LanProtocol(self),
            local_addr=("0.0.0.0", LAN_DISCOVERY_PORT),
            allow_broadcast=True,
        )
        self._running = True
        asyncio.create_task(self._broadcast_loop())
        print(f"[lan] discovery listening on port {LAN_DISCOVERY_PORT}")

    def stop(self):
        self._running = False
        if self._transport:
            self._transport.close()

    async def _broadcast_loop(self):
        while self._running:
            self._broadcast()
            await asyncio.sleep(LAN_DISCOVERY_INTERVAL)

    def _broadcast(self):
        payload = json.dumps({
            "magic":   LAN_DISCOVERY_MAGIC.decode(),
            "node_id": self.dht.node_id.hex(),
            "port":    self.dht_port,
        }).encode()
        if self._transport:
            try:
                self._transport.sendto(payload, ("255.255.255.255", LAN_DISCOVERY_PORT))
                print("[lan] broadcast sent")
            except Exception as e:
                print(f"[lan] broadcast error: {e}")

    def _handle(self, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            if msg.get("magic") != LAN_DISCOVERY_MAGIC.decode():
                return
            node_id = NodeID(bytes.fromhex(msg["node_id"]))
            if node_id == self.dht.node_id:
                return  # that's us
            peer = Peer(node_id, addr[0], msg["port"])
            self.dht.routing.add(peer)
            print(f"[lan] discovered peer {addr[0]}:{msg['port']}")
            # reply so they also discover us
            reply = json.dumps({
                "magic":   LAN_DISCOVERY_MAGIC.decode(),
                "node_id": self.dht.node_id.hex(),
                "port":    self.dht_port,
            }).encode()
            if self._transport:
                self._transport.sendto(reply, (addr[0], LAN_DISCOVERY_PORT))
        except Exception as e:
            print(f"[lan] parse error: {e}")


class _LanProtocol(asyncio.DatagramProtocol):
    def __init__(self, lan: LanDiscovery):
        self.lan = lan

    def datagram_received(self, data: bytes, addr: tuple):
        self.lan._handle(data, addr)

    def error_received(self, exc):
        print(f"[lan] udp error: {exc}")

    def connection_made(self, transport):
        # enable broadcast on socket
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


# ── sms gateway ────────────────────────────────────────────────

class SmsGateway:
    """
    optional SMS transport using android-sms-gateway.
    auto-detects cloud vs local based on SMS_URL:
      - if SMS_URL contains 'api.sms-gate.app' → cloud endpoint
      - anything else (e.g. http://192.168.1.5:8080) → local endpoint

    env vars:
        SMS=true
        SMS_URL   e.g. https://api.sms-gate.app  OR  http://192.168.1.5:8080
        SMS_USER
        SMS_PASS

    if SMS env var is missing or false, this is a no-op.
    if creds are blank at startup, SMS transport is skipped silently.
    """

    CLOUD_HOST = "api.sms-gate.app"
    CLOUD_PATH = "/3rdparty/v1/messages"
    LOCAL_PATH = "/message"

    def __init__(self):
        self.enabled   = False
        self.base_url  = None
        self.user      = None
        self.password  = None
        self._is_cloud = False

    def _endpoint(self) -> str:
        path = self.CLOUD_PATH if self._is_cloud else self.LOCAL_PATH
        return f"{self.base_url}{path}"

    async def setup(self):
        sms_env = os.environ.get("SMS", "false").lower()
        if sms_env in ("false", "0", "no", ""):
            print("[sms] disabled (SMS env not set or false)")
            return

        url  = os.environ.get("SMS_URL",  "").strip()
        user = os.environ.get("SMS_USER", "").strip()
        pwd  = os.environ.get("SMS_PASS", "").strip()

        if not url or not user or not pwd:
            print("[sms] SMS=true but credentials missing. enter them (blank = skip):")
            url  = url  or input("  gateway URL: ").strip()
            user = user or input("  username: ").strip()
            pwd  = pwd  or input("  password: ").strip()

        if not url or not user or not pwd:
            print("[sms] credentials blank — SMS transport disabled.")
            return

        self.base_url  = url.rstrip("/")
        self.user      = user
        self.password  = pwd
        self._is_cloud = self.CLOUD_HOST in self.base_url
        self.enabled   = True
        mode = "cloud" if self._is_cloud else "local"
        print(f"[sms] gateway configured ({mode}) → {self._endpoint()}")

    async def send(self, phone_number: str, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            import urllib.request, base64
            payload = json.dumps({
                "textMessage":  {"text": text},
                "phoneNumbers": [phone_number],
            }).encode()
            creds = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            req   = urllib.request.Request(
                self._endpoint(),
                data    = payload,
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Basic {creds}",
                },
                method = "POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = resp.status in (200, 201, 202)
                if not ok:
                    print(f"[sms] unexpected status {resp.status}")
                return ok
        except Exception as e:
            print(f"[sms] send failed: {e}")
            return False

    async def close(self):
        pass

# ── dht node ───────────────────────────────────────────────────

class DHTNode:
    def __init__(self, ip: str, port: int, node_id: NodeID = None):
        self.ip        = ip
        self.port      = port
        self.node_id   = node_id or NodeID.random()
        self.me        = Peer(self.node_id, ip, port)
        self.routing   = RoutingTable(self.node_id)
        self.store: dict[str, tuple[dict, float]] = {}
        self._transport = None
        self._protocol  = None
        self._pending: dict[str, asyncio.Future] = {}
        self.lan        = LanDiscovery(self, port)
        self.sms        = SmsGateway()

    async def start(self):
        loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self),
            local_addr=(self.ip, self.port)
        )
        print(f"[dht] node started on {self.ip}:{self.port}")
        print(f"[dht] node id: {self.node_id.hex()[:20]}...")

        await self.lan.start()
        await self.sms.setup()

    async def stop(self):
        self.lan.stop()
        await self.sms.close()
        if self._transport:
            self._transport.close()

    async def bootstrap(self, bootstrap_peers: list[tuple[str, int]]):
        print(f"[dht] bootstrapping with {len(bootstrap_peers)} peers...")
        for ip, port in bootstrap_peers:
            temp_id = NodeID.from_key(f"{ip}:{port}")
            peer    = Peer(temp_id, ip, port)
            await self.ping(peer)
        await self.find_node(self.node_id)
        print(f"[dht] bootstrap done. know {self.routing.total_peers()} peers.")

    async def ping(self, peer: Peer) -> bool:
        rpc_id = os.urandom(4).hex()
        msg    = make_msg(MSG_PING, self.me, rpc_id=rpc_id)
        try:
            resp = await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
            if resp and resp.get("type") == MSG_PONG:
                real_id      = NodeID(bytes.fromhex(resp["sender"]["node_id"]))
                peer.node_id = real_id
                self.routing.add(peer)
                return True
        except asyncio.TimeoutError:
            pass
        return False

    async def find_node(self, target: NodeID) -> list[Peer]:
        closest = self.routing.find_closest(target, ALPHA)
        if not closest:
            return []
        asked, results = set(), list(closest)
        while True:
            to_ask = [p for p in results if p.node_id.hex() not in asked][:ALPHA]
            if not to_ask:
                break
            for p in to_ask:
                asked.add(p.node_id.hex())
            responses = await asyncio.gather(
                *[self._rpc_find_node(p, target) for p in to_ask],
                return_exceptions=True
            )
            new_found = False
            for resp in responses:
                if isinstance(resp, list):
                    for pd in resp:
                        peer = Peer.from_dict(pd)
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
        target  = NodeID.from_key(key)
        closest = await self.find_node(target)
        await asyncio.gather(
            *[self._rpc_store(p, key, value) for p in closest[:K]],
            return_exceptions=True
        )
        print(f"[dht] stored '{key[:20]}...' on {len(closest)} nodes")

    async def get_value(self, key: str) -> Optional[dict]:
        target  = NodeID.from_key(key)
        closest = self.routing.find_closest(target, ALPHA)
        asked   = set()
        while True:
            to_ask = [p for p in closest if p.node_id.hex() not in asked][:ALPHA]
            if not to_ask:
                break
            for p in to_ask:
                asked.add(p.node_id.hex())
            responses = await asyncio.gather(
                *[self._rpc_find_value(p, key) for p in to_ask],
                return_exceptions=True
            )
            for resp in responses:
                if isinstance(resp, dict) and resp.get("found"):
                    return resp["value"]
                elif isinstance(resp, list):
                    for pd in resp:
                        peer = Peer.from_dict(pd)
                        if peer.node_id not in [c.node_id for c in closest]:
                            closest.append(peer)
        if key in self.store:
            val, expires = self.store[key]
            if time.time() < expires:
                return val
        return None

    async def announce(self, identity_bundle: dict):
        user_id = identity_bundle.get("user_id")
        if not user_id:
            raise ValueError("identity bundle must have a user_id")
        await self.store_value(user_id, identity_bundle)
        print(f"[dht] announced as {user_id[:24]}...")

    async def find_user(self, user_id: str) -> Optional[dict]:
        result = await self.get_value(user_id)
        print(f"[dht] {'found' if result else 'not found'}: {user_id[:24]}...")
        return result

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
            return await self._send_recv(peer.address, msg, rpc_id, TIMEOUT)
        except asyncio.TimeoutError:
            return None

    async def _send_recv(self, addr, msg, rpc_id, timeout) -> Optional[dict]:
        loop   = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending[rpc_id] = future
        self._transport.sendto(msg, addr)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(rpc_id, None)

    def _handle_message(self, data: bytes, addr: tuple):
        try:
            msg    = parse_msg(data)
            mtype  = msg.get("type")
            rpc_id = msg.get("rpc_id")
            sender = Peer.from_dict(msg["sender"])
            self.routing.add(sender)

            if rpc_id and rpc_id in self._pending:
                future = self._pending[rpc_id]
                if not future.done():
                    future.set_result(msg)
                return

            if mtype == MSG_PING:
                self._transport.sendto(
                    make_msg(MSG_PONG, self.me, rpc_id=rpc_id), addr)

            elif mtype == MSG_FIND_NODE:
                target  = NodeID(bytes.fromhex(msg["target"]))
                closest = self.routing.find_closest(target, K)
                self._transport.sendto(
                    make_msg(MSG_FIND_NODE_R, self.me, rpc_id=rpc_id,
                             peers=[p.to_dict() for p in closest]), addr)

            elif mtype == MSG_STORE:
                self.store[msg["key"]] = (msg["value"], time.time() + TTL)
                self._transport.sendto(
                    make_msg(MSG_STORE_R, self.me, rpc_id=rpc_id, ok=True), addr)

            elif mtype == MSG_FIND_VALUE:
                key = msg["key"]
                if key in self.store:
                    val, expires = self.store[key]
                    if time.time() < expires:
                        self._transport.sendto(
                            make_msg(MSG_FIND_VALUE_R, self.me, rpc_id=rpc_id,
                                     found=True, value=val), addr)
                        return
                target  = NodeID.from_key(key)
                closest = self.routing.find_closest(target, K)
                self._transport.sendto(
                    make_msg(MSG_FIND_VALUE_R, self.me, rpc_id=rpc_id,
                             found=False, peers=[p.to_dict() for p in closest]), addr)

        except Exception as e:
            print(f"[dht] error: {e}")


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: DHTNode):
        self.node = node

    def datagram_received(self, data: bytes, addr: tuple):
        self.node._handle_message(data, addr)

    def error_received(self, exc):
        print(f"[dht] udp error: {exc}")


# ── demo ───────────────────────────────────────────────────────

async def _demo():
    node_a = DHTNode("127.0.0.1", 9000)
    node_b = DHTNode("127.0.0.1", 9001)
    await node_a.start()
    await node_b.start()
    await node_b.bootstrap([("127.0.0.1", 9000)])
    fake_bundle = {"user_id": "enc1_test", "sign_pub": os.urandom(32).hex()}
    await node_a.store_value(fake_bundle["user_id"], fake_bundle)
    await asyncio.sleep(0.2)
    result = await node_b.get_value(fake_bundle["user_id"])
    print(f"found: {result is not None}")
    await node_a.stop()
    await node_b.stop()

if __name__ == "__main__":
    asyncio.run(_demo())
