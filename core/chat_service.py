# core/chat_service.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto import MessageCrypto, NoiseHandshake, PreCipher, RatchetSession
from storage import ChatStorage


@dataclass
class ChatBundle:
    pre_cipher: PreCipher
    ratchet: RatchetSession
    crypto: MessageCrypto


class ChatService:
    def __init__(self, chat_id: str, local_static_priv: X25519PrivateKey):
        self.chat_id = chat_id
        self.local_static_priv = local_static_priv
        self.storage = ChatStorage(chat_id)
        self.bundle: Optional[ChatBundle] = None
        self.shared_secret: Optional[bytes] = None
        self.chat_created_at = int(time.time())

    def start_handshake(self, remote_static_pub: bytes, is_initiator: bool = True) -> NoiseHandshake:
        return NoiseHandshake(is_initiator=is_initiator, local_static_priv=self.local_static_priv, remote_static_pub=remote_static_pub)

    def activate_session(self, shared_secret: bytes, chat_created_at: Optional[int] = None, is_initiator: bool = True, remote_ratchet_pub: Optional[bytes] = None) -> None:
        self.shared_secret = shared_secret
        if chat_created_at is not None:
            self.chat_created_at = chat_created_at
        pre = PreCipher.from_shared_secret(shared_secret, self.chat_created_at)
        ratchet = RatchetSession(shared_secret, is_initiator=is_initiator, remote_ratchet_pub=remote_ratchet_pub)
        self.bundle = ChatBundle(pre, ratchet, MessageCrypto(pre, ratchet))
        self.storage.save_session_state(ratchet.to_dict())
        self.storage.update_chat_data({"chat_created_at": self.chat_created_at, "active": True})

    def restore_session(self, shared_secret: bytes, session_state: dict[str, Any], chat_created_at: int) -> None:
        self.activate_session(shared_secret, chat_created_at=chat_created_at)
        if not self.bundle:
            return
        ratchet = self.bundle.ratchet
        ratchet.root_key = bytes.fromhex(session_state["root_key"])
        ratchet.send_counter = session_state.get("send_counter", 0)
        ratchet.recv_counter = session_state.get("recv_counter", 0)
        if session_state.get("send_chain_key"):
            ratchet.send_chain_key = bytes.fromhex(session_state["send_chain_key"])
        if session_state.get("recv_chain_key"):
            ratchet.recv_chain_key = bytes.fromhex(session_state["recv_chain_key"])
        if session_state.get("ratchet_pub"):
            ratchet.ratchet_pub = bytes.fromhex(session_state["ratchet_pub"])
        if session_state.get("remote_ratchet"):
            ratchet.remote_ratchet = bytes.fromhex(session_state["remote_ratchet"])
        self.storage.save_session_state(ratchet.to_dict())

    def send_message(self, plaintext: str, sender_id: Optional[str] = None) -> dict[str, Any]:
        if not self.bundle:
            raise RuntimeError("session not ready")
        payload = self.bundle.crypto.encrypt_message(plaintext)
        self.storage.save_message(payload, sender_id=sender_id)
        self.storage.save_session_state(self.bundle.ratchet.to_dict())
        return payload

    def receive_message(self, payload: dict[str, Any], sender_id: Optional[str] = None) -> str:
        if not self.bundle:
            raise RuntimeError("session not ready")
        plaintext = self.bundle.crypto.decrypt_message(payload)
        self.storage.save_message(payload, sender_id=sender_id)
        self.storage.save_session_state(self.bundle.ratchet.to_dict())
        return plaintext

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.storage.get_messages(limit=limit)

    def meta(self) -> dict[str, Any]:
        return self.storage.get_chat_meta()

    def close(self) -> None:
        if self.bundle:
            self.storage.save_session_state(self.bundle.ratchet.to_dict())
