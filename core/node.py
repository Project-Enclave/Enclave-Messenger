# core/node.py
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional, Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

from identity import PersonIdentity, DeviceBundle, ContactBook, Contact, KeyMismatchError, fingerprint
from dht import DHTNode, NodeID
from chat_service import ChatService


# ── config ─────────────────────────────────────────────────────

DATA_DIR      = Path.home() / ".enclave"
IDENTITY_FILE = DATA_DIR / "identity.json"
CONTACTS_FILE = DATA_DIR / "contacts.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"

DHT_PORT       = 9876
ANNOUNCE_EVERY = 1800

BOOTSTRAP_PEERS: list[tuple[str, int]] = [
    # ("1.2.3.4", 9876),
]


# ── message ─────────────────────────────────────────────────────

class Message:
    def __init__(self, sender_id: str, recipient_id: str, text: str,
                 timestamp: float = None, msg_id: str = None):
        self.sender_id    = sender_id
        self.recipient_id = recipient_id
        self.text         = text
        self.timestamp    = timestamp or time.time()
        self.msg_id       = msg_id or os.urandom(8).hex()

    def to_dict(self) -> dict:
        return {
            "msg_id":       self.msg_id,
            "sender_id":    self.sender_id,
            "recipient_id": self.recipient_id,
            "text":         self.text,
            "timestamp":    self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(d["sender_id"], d["recipient_id"], d["text"],
                   d["timestamp"], d["msg_id"])


# ── enclave node ────────────────────────────────────────────────

class EnclaveNode:
    """
    the main enclave node.
    wires identity + dht + crypto + storage into one place.
    create one, call start(), then use send_message() / receive_message().

    on_message: optional callback — called whenever an incoming message arrives.
                signature: on_message(msg: Message)
    """

    def __init__(self, on_message: Callable = None):
        self.identity  : Optional[PersonIdentity] = None
        self.device    : Optional[DeviceBundle]   = None
        self.contacts  : ContactBook              = ContactBook()
        self.dht       : Optional[DHTNode]        = None
        self.on_message: Optional[Callable]       = on_message
        self._sessions : dict[str, ChatService]   = {}   # user_id → ChatService
        self._running  : bool                     = False
        self._tasks    : list[asyncio.Task]        = []
        DATA_DIR.mkdir(exist_ok=True)

    # ── lifecycle ──────────────────────────────────────────────

    async def start(self, port: int = DHT_PORT):
        print("[node] starting...")
        self._load_or_create_identity()

        self.dht = DHTNode("0.0.0.0", port,
                           node_id=NodeID.from_key(self.identity.user_id))
        await self.dht.start()

        if BOOTSTRAP_PEERS:
            await self.dht.bootstrap(BOOTSTRAP_PEERS)
        else:
            print("[node] no bootstrap peers — running in local/LAN mode.")

        await self._announce()
        self._load_contacts()
        self._load_sessions()

        self._running = True
        self._tasks.append(asyncio.create_task(self._announce_loop()))

        print(f"[node] ready.  user_id:     {self.identity.user_id}")
        print(f"[node]         fingerprint: {self.identity.fingerprint}")

    async def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        if self.dht:
            await self.dht.stop()
        self._save_sessions()
        print("[node] stopped.")

    # ── contacts ──────────────────────────────────────────────

    async def add_contact(self, user_id: str) -> Optional[Contact]:
        """
        look up a user on the DHT, verify their prekey, run the
        Noise handshake, and open a ChatService session with them.
        """
        print(f"[node] looking up {user_id[:24]}...")
        bundle = await self.dht.find_user(user_id)
        if not bundle:
            print("[node] user not found — they may be offline.")
            return None

        try:
            contact = self.contacts.add_contact(bundle)
        except KeyMismatchError as e:
            print(f"[node] KEY MISMATCH: {e}")
            return None

        if not contact.verify_prekey():
            print("[node] prekey signature invalid — rejecting.")
            return None

        # ── Noise handshake (initiator side) ──────────────────
        remote_static_pub = contact.signed_prekey_pub
        hs = ChatService(user_id, self.device._signed_prekey).start_handshake(
            remote_static_pub, is_initiator=True
        )

        # step 1 — send our ephemeral pub to the peer via DHT
        msg1 = hs.step1_initiator()
        hs_key = f"hs_{self.identity.user_id}_{user_id}"
        await self.dht.store_value(hs_key, {"step": 1, "payload": msg1.hex()})

        # step 3 — retrieve responder's reply
        await asyncio.sleep(0.5)
        reply = await self.dht.get_value(f"hs_{user_id}_{self.identity.user_id}")

        if reply and reply.get("step") == 2:
            msg2    = bytes.fromhex(reply["payload"])
            msg3    = hs.step3_initiator(msg2)
            # send our static pub to finish the handshake
            await self.dht.store_value(hs_key, {"step": 3, "payload": msg3.hex()})

            if hs.complete and hs.shared_secret:
                self._open_session(user_id, hs.shared_secret)
                self._save_contacts()
                self._save_sessions()
                print(f"[node] session established with {contact.display_name}")
                return contact
        else:
            # peer is not online right now — save contact, skip live handshake.
            # session will be opened when they come online and complete the handshake.
            self._save_contacts()
            print(f"[node] contact saved. session will open when they come online.")
            return contact

        return None

    async def complete_incoming_handshake(self, initiator_user_id: str) -> bool:
        """
        called when a remote peer has initiated a handshake with us.
        looks up their step-1 message, runs the responder side,
        and opens a session.
        """
        hs_key  = f"hs_{initiator_user_id}_{self.identity.user_id}"
        hs_data = await self.dht.get_value(hs_key)
        if not hs_data or hs_data.get("step") != 1:
            return False

        contact = self.contacts.get(initiator_user_id)
        if not contact:
            print(f"[node] unknown initiator {initiator_user_id[:24]} — add them first.")
            return False

        msg1 = bytes.fromhex(hs_data["payload"])
        hs   = ChatService(initiator_user_id, self.device._signed_prekey).start_handshake(
            contact.signed_prekey_pub, is_initiator=False
        )
        msg2 = hs.step2_responder(msg1)

        # send our reply
        reply_key = f"hs_{self.identity.user_id}_{initiator_user_id}"
        await self.dht.store_value(reply_key, {"step": 2, "payload": msg2.hex()})

        # wait for step 3
        await asyncio.sleep(0.5)
        step3_data = await self.dht.get_value(hs_key)
        if step3_data and step3_data.get("step") == 3:
            hs.step4_responder_finish(bytes.fromhex(step3_data["payload"]))
            if hs.complete and hs.shared_secret:
                self._open_session(initiator_user_id, hs.shared_secret)
                self._save_sessions()
                print(f"[node] session established with {contact.display_name}")
                return True

        return False

    def get_contact(self, user_id: str) -> Optional[Contact]:
        return self.contacts.get(user_id)

    def list_contacts(self) -> list[dict]:
        return self.contacts.all_contacts()

    # ── messaging ─────────────────────────────────────────────

    async def send_message(self, recipient_id: str, text: str) -> bool:
        """
        encrypt and send a message to a contact.
        message is encrypted with their ChatService session key,
        then stored on the DHT for them to retrieve.
        """
        session = self._sessions.get(recipient_id)
        if not session:
            print(f"[node] no session with {recipient_id[:24]} — handshake needed.")
            return False

        contact = self.contacts.get(recipient_id)
        if not contact:
            print(f"[node] unknown contact {recipient_id[:24]}.")
            return False

        payload  = session.send_message(text, sender_id=self.identity.user_id)
        inbox_key = f"inbox_{recipient_id}_{os.urandom(4).hex()}"
        await self.dht.store_value(inbox_key, {
            "type":      "message",
            "sender_id": self.identity.user_id,
            "payload":   payload,
        })

        self._save_sessions()
        print(f"[node] sent to {contact.display_name}")
        return True

    async def receive_message(self, sender_id: str, raw: dict) -> Optional[Message]:
        """
        decrypt an incoming encrypted payload from a known sender.
        raw is the dict retrieved from the DHT inbox key.
        """
        session = self._sessions.get(sender_id)
        if not session:
            print(f"[node] no session with {sender_id[:24]} — can't decrypt.")
            return None

        plaintext = session.receive_message(raw["payload"], sender_id=sender_id)
        msg = Message(
            sender_id    = sender_id,
            recipient_id = self.identity.user_id,
            text         = plaintext,
        )
        self._save_sessions()
        if self.on_message:
            self.on_message(msg)
        return msg
    
    async def send_message_sms(self, recipient_id: str, text: str, phone: str) -> bool:
    """
    encrypt a message and deliver it via SMS gateway.
    used as fallback when DHT/internet is unavailable.
    the SMS body is a JSON-encoded encrypted payload — not plaintext.
    """
    session = self._sessions.get(recipient_id)
    if not session:
        print(f"[node] no session with {recipient_id[:24]} — handshake needed.")
        return False

    payload = session.send_message(text, sender_id=self.identity.user_id)
    encoded = json.dumps({
        "type":      "enclave",
        "sender_id": self.identity.user_id,
        "payload":   payload,
    })
    ok = await self.dht.sms.send(phone, encoded)
    if ok:
        self._save_sessions()
        print(f"[node] SMS sent to {phone}")
    return ok

    def conversation(self, user_id: str, limit: int = 100) -> list[dict]:
        """get stored message history with a contact"""
        session = self._sessions.get(user_id)
        if not session:
            return []
        return session.history(limit=limit)

    # ── session management ────────────────────────────────────

    def _open_session(self, user_id: str, shared_secret: bytes,
                      is_initiator: bool = True) -> ChatService:
        service = ChatService(
            chat_id          = f"{self.identity.user_id[:16]}_{user_id[:16]}",
            local_static_priv= self.device._signed_prekey,
        )
        service.activate_session(
            shared_secret   = shared_secret,
            chat_created_at = int(time.time()),
            is_initiator    = is_initiator,
        )
        self._sessions[user_id] = service
        return service

    def _save_sessions(self):
        data = {}
        for uid, svc in self._sessions.items():
            meta = svc.meta()
            if svc.shared_secret and meta:
                data[uid] = {
                    "shared_secret":   svc.shared_secret.hex(),
                    "chat_created_at": svc.chat_created_at,
                    "session_state":   svc.storage.load_session_state(),
                }
        SESSIONS_FILE.write_text(json.dumps(data, indent=2))

    def _load_sessions(self):
        if not SESSIONS_FILE.exists():
            return
        try:
            data = json.loads(SESSIONS_FILE.read_text())
        except Exception:
            return
        for uid, saved in data.items():
            service = ChatService(
                chat_id          = f"{self.identity.user_id[:16]}_{uid[:16]}",
                local_static_priv= self.device._signed_prekey,
            )
            service.restore_session(
                shared_secret   = bytes.fromhex(saved["shared_secret"]),
                session_state   = saved["session_state"],
                chat_created_at = saved["chat_created_at"],
            )
            self._sessions[uid] = service
        print(f"[node] restored {len(self._sessions)} session(s).")

    # ── identity ──────────────────────────────────────────────

    def _load_or_create_identity(self):
        if IDENTITY_FILE.exists():
            print("[node] loading existing identity...")
            raw = json.loads(IDENTITY_FILE.read_text())
            self.identity = _restore_identity(raw)
            self.device   = _restore_device(raw, self.identity)
        else:
            print("[node] generating new identity...")
            self.identity = PersonIdentity()
            self.device   = DeviceBundle(self.identity, "main")
            self._save_identity()
            print(f"[node] fingerprint: {self.identity.fingerprint}")
            print(f"[node] SAVE THIS — it's how contacts verify you.")

    def _save_identity(self):
        data = {
            "user_id":             self.identity.user_id,
            "sign_pub":            self.identity.sign_pub.hex(),
            "sign_priv":           self.identity._sign_key.private_bytes_raw().hex(),
            "signed_prekey_pub":   self.device.signed_prekey_pub.hex(),
            "signed_prekey_priv":  self.device._signed_prekey.private_bytes(
                                       Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                                   ).hex(),
            "signed_prekey_sig":   self.device.signed_prekey_sig.hex(),
            "device_id":           self.device.device_id,
            "device_label":        self.device.device_label,
            "one_time_pubs":       [p.hex() for p in self.device.one_time_pubs],
            "created_at":          self.identity.created_at,
        }
        IDENTITY_FILE.write_text(json.dumps(data, indent=2))

    def _save_contacts(self):
        CONTACTS_FILE.write_text(
            json.dumps(self.contacts.all_contacts(), indent=2)
        )

    def _load_contacts(self):
        # contact public info is cached locally but full bundles
        # (including prekeys) are re-fetched from DHT when needed
        pass

    # ── background ────────────────────────────────────────────

    async def _announce_loop(self):
        while self._running:
            await asyncio.sleep(ANNOUNCE_EVERY)
            await self._announce()

    async def _announce(self):
        await self.dht.announce(self.device.export_public(self.identity))

    # ── properties ────────────────────────────────────────────

    @property
    def user_id(self) -> str:
        return self.identity.user_id if self.identity else None

    @property
    def fp(self) -> str:
        return self.identity.fingerprint if self.identity else None


# ── identity restore helpers ───────────────────────────────────

def _restore_identity(raw: dict) -> PersonIdentity:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    identity             = object.__new__(PersonIdentity)
    identity._sign_key   = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw["sign_priv"]))
    identity.sign_pub    = bytes.fromhex(raw["sign_pub"])
    identity.user_id     = raw["user_id"]
    identity.created_at  = raw["created_at"]
    identity.fingerprint = fingerprint(identity.sign_pub)
    return identity

def _restore_device(raw: dict, identity: PersonIdentity) -> DeviceBundle:
    device                    = object.__new__(DeviceBundle)
    device.device_id          = raw["device_id"]
    device.device_label       = raw["device_label"]
    device.signed_prekey_pub  = bytes.fromhex(raw["signed_prekey_pub"])
    device.signed_prekey_sig  = bytes.fromhex(raw["signed_prekey_sig"])
    device.one_time_pubs      = [bytes.fromhex(p) for p in raw.get("one_time_pubs", [])]
    device._one_time_keys     = []
    device.capabilities       = {"internet": True, "lan": True, "bluetooth": False, "lora": False}
    if raw.get("signed_prekey_priv"):
        device._signed_prekey = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(raw["signed_prekey_priv"])
        )
    else:
        # old identity file without saved prekey priv — regenerate
        device._signed_prekey    = X25519PrivateKey.generate()
        device.signed_prekey_pub = device._signed_prekey.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
    return device


# ── demo ───────────────────────────────────────────────────────

async def _demo():
    def on_msg(msg: Message):
        print(f"[inbox] {msg.sender_id[:16]}...: {msg.text}")

    node = EnclaveNode(on_message=on_msg)
    await node.start(port=9876)
    print(f"\nuser_id:     {node.user_id}")
    print(f"fingerprint: {node.fp}")
    print(f"contacts:    {len(node.list_contacts())}")
    print(f"sessions:    {len(node._sessions)}")
    await asyncio.sleep(2)
    await node.stop()

if __name__ == "__main__":
    asyncio.run(_demo())
