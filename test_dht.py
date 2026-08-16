"""
test_dht.py — tests for core/network/dht.py and its integration into
core/network/router.py's Node class.

Scope note, honestly: this covers the core protocol (bootstrap, routing
table population, iterative find_node, announce/find_value, self-storage,
address self-detection, the key-pinning security cross-check) and one
real end-to-end send() through Node using DHT as the only way the peer
was ever known. It does NOT exhaustively test routing table behavior at
scale (hundreds of nodes, bucket splitting edge cases) or adversarial
DHT scenarios beyond the single key-mismatch check — those would be
their own substantial testing effort if this ever needs to run against
a real, larger, adversarial swarm rather than a handful of trusted local
nodes.

Run: python3 test_dht.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.network.dht import DHTNode, node_id_for, key_for
from core.storage import ConfigStore, ChatStore, PeerStore
from core.identity.key_manager import IdentityManager
from core.network.router import Node

PASS, FAIL = [], []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def test_core_protocol():
    check("node_id_for is deterministic", node_id_for("alice") == node_id_for("alice"))
    check("node_id_for differs for different inputs", node_id_for("alice") != node_id_for("bob"))
    check("key_for(x) == node_id_for(x) — same hash space", key_for("alice") == node_id_for("alice"))
    check("node_id fits in 160 bits", node_id_for("alice").bit_length() <= 160)

    tmp_a, tmp_b, tmp_c = tempfile.mkdtemp(), tempfile.mkdtemp(), tempfile.mkdtemp()
    peers_a, peers_b, peers_c = PeerStore(base_dir=tmp_a), PeerStore(base_dir=tmp_b), PeerStore(base_dir=tmp_c)

    alice = DHTNode("alice_uid", 59101, peers_a)
    bob = DHTNode("bob_uid", 59102, peers_b)
    carol = DHTNode("carol_uid", 59103, peers_c)

    alice.start()
    bob.start(bootstrap_addrs=["127.0.0.1:59101"])
    time.sleep(0.3)
    carol.start(bootstrap_addrs=["127.0.0.1:59101"])
    time.sleep(0.5)

    check("alice's routing table learned about bob (he queried her)",
          any(c.node_id == bob.self_id for bucket in alice.table.buckets for c in bucket))
    check("bob's routing table learned about alice (from the RPC response)",
          any(c.node_id == alice.self_id for bucket in bob.table.buckets for c in bucket))
    check("carol's find_node locates alice",
          any(c.node_id == alice.self_id for c in carol.find_node(alice.self_id)))

    learned = bob.learn_own_address()
    check("bob learned his own apparent address via ping echo", learned is not None)

    bob.set_identity_payload(ed25519_pub="bob_ed", x25519_pub="bob_x", transport_port=9999)
    bob.announce_self()
    time.sleep(0.3)

    result = carol.find_peer("bob_uid")
    check("carol found bob via DHT find_peer", result is not None)
    if result:
        check("resolved peer has correct user_id", result["user_id"] == "bob_uid")
        check("resolved peer has correct pubkeys", result["ed25519_pub"] == "bob_ed")
        check("resolved peer has a real, non-empty ip", bool(result.get("ip")))
        check("resolved peer was written into carol's peer_store", peers_c.get("bob_uid") is not None)

    missing = carol.find_peer("nobody_ever_announced_this_id")
    check("looking up someone who never announced returns None", missing is None)

    # Security: a DHT result for an ALREADY-KNOWN peer with DIFFERENT keys
    # must be rejected exactly like a spoofed LAN broadcast would be.
    peers_c.upsert(user_id="bob_uid", username="bob", ed25519_pub="REAL_bob_ed",
                   x25519_pub="REAL_bob_x", ip="1.2.3.4", port=1111)
    spoofed = {"user_id": "bob_uid", "ed25519_pub": "ATTACKER_KEY", "x25519_pub": "ATTACKER_KEY",
               "ip": "6.6.6.6", "port": 6666}
    rejected = carol._verify_and_store(spoofed)
    check("DHT result with mismatched keys for a known peer is rejected", rejected is None)
    check("peer_store keeps the real pinned key, not the spoofed one",
          peers_c.get("bob_uid")["ed25519_pub"] == "REAL_bob_ed")

    # Explicit public_ip override takes priority over auto-detection.
    tmp_d = tempfile.mkdtemp()
    peers_d = PeerStore(base_dir=tmp_d)
    dave = DHTNode("dave_uid", 59104, peers_d)
    dave.start(bootstrap_addrs=["127.0.0.1:59101"])
    time.sleep(0.3)
    dave.set_identity_payload(ed25519_pub="dave_ed", x25519_pub="dave_x", transport_port=7777,
                                public_ip="203.0.113.42")
    dave.announce_self()
    time.sleep(0.3)
    result2 = carol.find_peer("dave_uid")
    check("explicit public_ip override is used instead of auto-detection",
          result2 is not None and result2.get("ip") == "203.0.113.42")

    alice.stop(); bob.stop(); carol.stop(); dave.stop()


def test_node_integration():
    """
    The real end-to-end claim: Node.send() to a peer known ONLY through
    DHT — never seen on a LAN, never manually paired — actually delivers.
    """
    tmp = tempfile.mkdtemp()

    def mk(label, transport_port, dht_port, bootstrap=None, public_ip=None):
        d = os.path.join(tmp, label)
        os.makedirs(d)
        im = IdentityManager(storage_dir=os.path.join(d, "identity"))
        im.generate_new_identity()
        cfg = ConfigStore(base_dir=d)
        cfg.set_setting("network_port", transport_port)
        cfg.set_setting("dht_enabled", True)
        cfg.set_setting("dht_port", dht_port)
        if bootstrap:
            cfg.set_setting("dht_bootstrap", bootstrap)
        if public_ip:
            cfg.set_setting("dht_public_ip", public_ip)
        chats = ChatStore(base_dir=d)
        peers = PeerStore(base_dir=d)
        return Node(im, cfg, peers, chats), peers, chats

    # Explicit public_ip="127.0.0.1" on both sides — this sandbox's
    # container networking rewrites loopback UDP source addresses in a
    # way that makes pure self-detection (the ping-echo/STUN-style
    # technique in learn_own_address()) resolve to an address that isn't
    # actually dialable here specifically. That's a property of this
    # container, not of the technique — confirmed by reproducing the
    # same rewritten-address behavior with raw sockets, nothing
  # DHT-specific about it. A real deployment (or two real machines
    # on the actual internet, which is what this technique is standard
    # for) doesn't have this problem. The override exists for exactly
    # this kind of environment anyway, so this test uses it rather than
    # asserting on a sandbox artifact.
    alice, ap, ac = mk("alice", 59201, 59251, bootstrap=None, public_ip="127.0.0.1")
    bob, bp, bc = mk("bob", 59202, 59252, bootstrap=["127.0.0.1:59251"], public_ip="127.0.0.1")

    check("Node constructs a DHT instance when dht_enabled=True", alice._dht is not None)

    alice.start()
    time.sleep(0.2)
    bob.start()
    time.sleep(1.0)

    check("bob's peer_store does NOT already know alice (sanity check)",
          bp.get(alice._identity["user_id"]) is None)

    ok = bob.send(alice._identity["user_id"], "found you via DHT, no LAN/manual pairing at all")
    time.sleep(0.3)
    check("bob.send() to a DHT-only peer succeeds", ok)

    alice_inbox = ac.load_messages(bob._identity["user_id"])
    check("alice actually received the message", len(alice_inbox) == 1)

    resolved = bp.get(alice._identity["user_id"])
    check("bob's peer_store now has alice, with the correct address",
          resolved is not None and resolved.get("ip") == "127.0.0.1"
          and resolved.get("port") == 59201)

    alice.stop(); bob.stop()


def main():
    test_core_protocol()
    test_node_integration()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
