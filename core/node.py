# core/node.py
# the brain of enclave messenger
# wires together identity + dht + (later) crypto + transport
# everything above this is just ui
# ----------------------------------------------------------
# usage:
#   node = EnclaveNode()
#   await node.start()
#   await node.send_message(user_id, "hey")

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional, Callable

from identity import PersonIdentity, DeviceBundle, ContactBook, Contact, KeyMismatchError
from dht import DHTNode, NodeID


# ── config ─────────────────────────────────────────────────────

DATA_DIR        = Path.home() / ".enclave"
IDENTITY_FILE   = DATA_DIR / "identity.json"
CONTACTS_FILE   = DATA_DIR / "contacts.json"
MESSAGES_FILE   = DATA_DIR / "messages.json"

DHT_PORT        = 9876
ANNOUNCE_EVERY  = 1800   # re-announce identity to DHT every 30 min

# hardcoded bootstrap peers — these are just known-good enclave nodes
# you'll replace these with real ones when the network exists
BOOTSTRAP_PEERS = [
    # ("1.2.3.4", 9876),  # ← add real peers here later
]


# ── message ─────────────────────────────────────────────────────

class Message:
    """a single message in a conversation"""

    def __init__(self, sender_id: str, recipient_id: str, text: str,
                 timestamp: float = None, msg_id: str = None):
        self.sender_id    = sender_id
        self.recipient_id = recipient_id
        self.text         = text
        self.timestamp    = timestamp or time.time()
        self.msg_id       = msg_id or os.urandom(8).hex()
        self.delivered    = False

    def to_dict(self) -> dict:
        return {
            "msg_id":       self.msg_id,
            "sender_id":    self.sender_id,
            "recipient_id": self.recipient_id,
            "text":         self.text,
            "timestamp":    self.timestamp,
            "delivered":    self.delivered,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        m           = cls(d["sender_id"], d["recipient_id"], d["text"],
                          d["timestamp"], d["msg_id"])
        m.delivered = d.get("delivered", False)
        return m


# ── enclave node ────────────────────────────────────────────────

class EnclaveNode:
    """
    the main enclave node.
    create one of these, call start(), and everything else follows.

    on_message: callback called whenever a message arrives
                signature: on_message(msg: Message)
    """

    def __init__(self, on_message: Callable = None):
        self.identity    : Optional[PersonIdentity] = None
        self.device      : Optional[DeviceBundle]   = None
        self.contacts    : ContactBook              = ContactBook()
        self.dht         : Optional[DHTNode]        = None
        self.on_message  : Optional[Callable]       = on_message
        self._messages   : list[Message]            = []
        self._running    : bool                     = False
        self._tasks      : list[asyncio.Task]       = []

        DATA_DIR.mkdir(exist_ok=True)

    # ── lifecycle ──

    async def start(self, port: int = DHT_PORT):
        print("[node] starting enclave node...")

        # load or create identity
        self._load_or_create_identity()

        # start DHT
        self.dht = DHTNode("0.0.0.0", port,
                           node_id=NodeID.from_key(self.identity.user_id))
        await self.dht.start()

        # bootstrap into the network
        if BOOTSTRAP_PEERS:
            await self.dht.bootstrap(BOOTSTRAP_PEERS)
        else:
            print("[node] no bootstrap peers configured. running in local/LAN mode for now.")

        # announce our identity so others can find us
        await self._announce()

        # load saved contacts + messages
        self._load_contacts()
        self._load_messages()

        # background tasks
        self._running = True
        self._tasks.append(asyncio.create_task(self._announce_loop()))

        print(f"[node] ready. user id: {self.identity.user_id[:32]}...")
        print(f"[node] fingerprint: {self.identity.fingerprint}")

    async def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self.dht:
            await self.dht.stop()
        self._save_messages()
        print("[node] stopped.")

    # ── identity ──

    def _load_or_create_identity(self):
        if IDENTITY_FILE.exists():
            print("[node] loading existing identity...")
            raw = json.loads(IDENTITY_FILE.read_text())
            # TODO: decrypt with passphrase before loading
            # for now just rebuild from stored keys
            self.identity = _restore_identity(raw)
            self.device   = _restore_device(raw, self.identity)
        else:
            print("[node] no identity found. generating new one...")
            self.identity = PersonIdentity()
            self.device   = DeviceBundle(self.identity, "main")
            self._save_identity()
            print(f"[node] new identity created.")
            print(f"[node] fingerprint: {self.identity.fingerprint}")
            print(f"[node] SAVE THIS FINGERPRINT. it's how contacts verify you're you.")

    def _save_identity(self):
        # TODO: encrypt with passphrase before saving to disk
        data = {
            "user_id":           self.identity.user_id,
            "sign_pub":          self.identity.sign_pub.hex(),
            "sign_priv":         self.identity._sign_key.private_bytes_raw().hex(),
            "signed_prekey_pub": self.device.signed_prekey_pub.hex(),
            "signed_prekey_sig": self.device.signed_prekey_sig.hex(),
            "device_id":         self.device.device_id,
            "device_label":      self.device.device_label,
            "one_time_pubs":     [p.hex() for p in self.device.one_time_pubs],
            "created_at":        self.identity.created_at,
        }
        IDENTITY_FILE.write_text(json.dumps(data, indent=2))

    # ── contacts ──

    async def add_contact_by_id(self, user_id: str) -> Optional[Contact]:
        """
        look up a user by their user_id in the DHT and add them as a contact.
        this is the main way to add someone on enclave.
        """
        print(f"[node] looking up {user_id[:24]}...")
        bundle = await self.dht.find_user(user_id)
        if not bundle:
            print("[node] user not found. they might be offline.")
            return None
        try:
            contact = self.contacts.add_contact(bundle)
            if not contact.verify_prekey():
                print("[node] WARNING: prekey signature invalid. rejecting contact.")
                return None
            self._save_contacts()
            print(f"[node] added contact: {contact.display_name}")
            return contact
        except KeyMismatchError as e:
            print(f"[node] KEY MISMATCH: {e}")
            return None

    def get_contact(self, user_id: str) -> Optional[Contact]:
        return self.contacts.get(user_id)

    def list_contacts(self) -> list[dict]:
        return self.contacts.all_contacts()

    # ── messaging ──

    async def send_message(self, recipient_id: str, text: str) -> bool:
        """
        send a message to a contact by their user_id.
        right now this is plaintext over DHT — encryption comes next.
        """
        contact = self.contacts.get(recipient_id)
        if not contact:
            print(f"[node] unknown contact: {recipient_id[:24]}. add them first.")
            return False

        msg = Message(
            sender_id    = self.identity.user_id,
            recipient_id = recipient_id,
            text         = text,
        )

        # TODO: encrypt msg with double ratchet session key before storing
        # for now storing plaintext as a DHT proof-of-concept
        # DO NOT use this in production without encryption
        payload = {
            "type":    "message",
            "msg":     msg.to_dict(),
        }
        store_key = f"msg_{recipient_id}_{msg.msg_id}"
        await self.dht.store_value(store_key, payload)

        self._messages.append(msg)
        self._save_messages()
        print(f"[node] sent message to {contact.display_name}")
        return True

    async def check_messages(self):
        """
        poll DHT for messages addressed to us.
        in a real implementation this would be push-based via direct connection.
        for now, polling is fine for the proof of concept.
        """
        # TODO: replace with direct peer connection + push delivery
        pass

    def get_conversation(self, user_id: str) -> list[Message]:
        """get all messages with a specific contact"""
        return [m for m in self._messages
                if m.sender_id == user_id or m.recipient_id == user_id]

    def get_all_messages(self) -> list[Message]:
        return list(self._messages)

    # ── background tasks ──

    async def _announce_loop(self):
        """re-announce our identity periodically so we stay discoverable"""
        while self._running:
            await asyncio.sleep(ANNOUNCE_EVERY)
            await self._announce()

    async def _announce(self):
        bundle = self.device.export_public(self.identity)
        await self.dht.announce(bundle)

    # ── persistence ──

    def _save_contacts(self):
        data = self.contacts.all_contacts()
        CONTACTS_FILE.write_text(json.dumps(data, indent=2))

    def _load_contacts(self):
        if CONTACTS_FILE.exists():
            # contacts file only has public info, not full bundles
            # full bundles would need to be re-fetched from DHT
            pass  # TODO: load cached contact public info

    def _save_messages(self):
        data = [m.to_dict() for m in self._messages]
        MESSAGES_FILE.write_text(json.dumps(data, indent=2))

    def _load_messages(self):
        if MESSAGES_FILE.exists():
            data = json.loads(MESSAGES_FILE.read_text())
            self._messages = [Message.from_dict(d) for d in data]

    # ── utils ──

    @property
    def user_id(self) -> str:
        return self.identity.user_id if self.identity else None

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint if self.identity else None


# ── identity restore helpers ────────────────────────────────────
# these live here and not in identity.py to keep identity.py clean
# identity.py doesn't need to know about file formats

def _restore_identity(raw: dict) -> PersonIdentity:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    identity = object.__new__(PersonIdentity)
    identity._sign_key   = Ed25519PrivateKey.from_private_bytes(
                               bytes.fromhex(raw["sign_priv"]))
    identity.sign_pub    = bytes.fromhex(raw["sign_pub"])
    identity.user_id     = raw["user_id"]
    identity.created_at  = raw["created_at"]
    from identity import fingerprint
    identity.fingerprint = fingerprint(identity.sign_pub)
    return identity

def _restore_device(raw: dict, identity: PersonIdentity) -> DeviceBundle:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    device = object.__new__(DeviceBundle)
    device.device_id         = raw["device_id"]
    device.device_label      = raw["device_label"]
    device.signed_prekey_pub = bytes.fromhex(raw["signed_prekey_pub"])
    device.signed_prekey_sig = bytes.fromhex(raw["signed_prekey_sig"])
    device.one_time_pubs     = [bytes.fromhex(p) for p in raw.get("one_time_pubs", [])]
    device._one_time_keys    = []   # can't restore privkeys from pub, regenerate on next start
    device._signed_prekey    = None # same
    device.capabilities      = {
        "internet": True, "lan": True, "bluetooth": False, "lora": False
    }
    return device


# ── quick demo ──────────────────────────────────────────────────

async def _demo():
    def on_msg(msg):
        print(f"[inbox] {msg.sender_id[:16]}...: {msg.text}")

    node = EnclaveNode(on_message=on_msg)
    await node.start(port=9876)

    print(f"\nuser id:     {node.user_id}")
    print(f"fingerprint: {node.fingerprint}")
    print(f"contacts:    {len(node.list_contacts())}")

    # keep running for a bit
    await asyncio.sleep(2)
    await node.stop()

if __name__ == "__main__":
    asyncio.run(_demo())
