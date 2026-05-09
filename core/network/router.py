"""
router.py — Top-level Node: the single object main.py creates.

Usage:
    node = Node(identity, config, peer_store, chat_store)
    node.start()   # background threads: discovery + transport
    node.send(peer_user_id, plaintext)  # encrypt + deliver
    node.stop()

Inbound messages are automatically decrypted and written to ChatStore.
"""

import logging
from datetime import datetime, timezone

from .discovery import Discovery
from .transport import Transport
from core.crypto import CryptoManager

log = logging.getLogger("network")

TRANSPORT_PORT = 51821  # HTTP transport port (separate from Flask's 5000)


class Node:
    def __init__(self, identity_manager, config_store, peer_store, chat_store):
        """
        identity_manager: IdentityManager (keys already loaded)
        config_store:     ConfigStore
        peer_store:       PeerStore
        chat_store:       ChatStore
        """
        self._im       = identity_manager
        self._config   = config_store
        self._peers    = peer_store
        self._chats    = chat_store
        self._passphrase = None  # set via node.set_passphrase() after unlock

        self._identity = self._build_identity()
        port = config_store.get_setting("network_port") or TRANSPORT_PORT

        self._transport = Transport(
            host="0.0.0.0",
            port=port,
            on_message=self._on_inbound,
        )
        self._discovery = Discovery(
            identity=self._identity,
            transport_port=port,
            peer_store=peer_store,
            on_peer_found=self._on_peer_found,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._transport.start()
        self._discovery.start()
        log.info("[node] started — user_id: %s", self._identity["user_id"][:16])

    def stop(self):
        self._discovery.stop()
        self._transport.stop()
        log.info("[node] stopped")

    # ------------------------------------------------------------------
    # Passphrase (needed for encrypt/decrypt)
    # ------------------------------------------------------------------

    def set_passphrase(self, passphrase: str):
        self._passphrase = passphrase

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send(self, peer_user_id: str, plaintext: str) -> bool:
        """
        Encrypt plaintext and deliver to peer over HTTP transport.
        Returns True if delivered, False otherwise.
        Raises RuntimeError if the node is locked (no passphrase set).
        """
        peer = self._peers.get(peer_user_id)
        if not peer:
            log.warning("[node] send: unknown peer %s", peer_user_id[:12])
            return False
        if not peer.get("ip") or not peer.get("port"):
            log.warning("[node] send: no address for peer %s", peer_user_id[:12])
            return False

        if not self._passphrase:
            raise RuntimeError("Node is locked — call set_passphrase() before sending.")

        ts    = datetime.now(timezone.utc).isoformat()
        token = CryptoManager(self._passphrase).encrypt(
            plaintext=plaintext,
            chat_id=peer_user_id,
            created_at=ts,
        )

        envelope = {
            "from":    self._identity["user_id"],
            "chat_id": peer_user_id,
            "token":   token,
            "ts":      ts,
        }

        address = f"http://{peer['ip']}:{peer['port']}"
        ok = self._transport.send(address, envelope)
        if ok:
            log.info("[node] delivered to %s", peer_user_id[:12])
        return ok

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def _on_inbound(self, envelope: dict):
        sender_id = envelope.get("from", "")
        chat_id   = envelope.get("chat_id", self._identity["user_id"])
        token     = envelope.get("token", "")
        ts        = envelope.get("ts", datetime.now(timezone.utc).isoformat())

        if not sender_id or not token:
            log.warning("[node] inbound: malformed envelope")
            return

        # Store raw token — web.py decrypts on demand (same as existing flow)
        self._chats.append_message(sender_id, {
            "token":  token,
            "sender": sender_id,
            "ts":     ts,
        })
        log.info("[node] inbound message from %s", sender_id[:12])

    # ------------------------------------------------------------------
    # Peer events
    # ------------------------------------------------------------------

    def _on_peer_found(self, peer: dict):
        log.info("[node] peer found: %s (%s) @ %s",
                 peer.get("username", "?"),
                 peer.get("user_id", "")[:12],
                 peer.get("ip", "?"))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_identity(self) -> dict:
        from cryptography.hazmat.primitives import serialization
        import base64

        def raw_pub(key) -> str:
            b = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return base64.urlsafe_b64encode(b).decode("utf-8")

        return {
            "user_id":    self._im.get_user_id(),
            "username":   self._config.username or "",
            "ed25519_pub": raw_pub(self._im.ed25519_priv),
            "x25519_pub":  raw_pub(self._im.x25519_priv),
        }
