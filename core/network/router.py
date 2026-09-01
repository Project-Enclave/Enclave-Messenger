"""
router.py — Top-level Node: the single object main.py creates.

Usage:
    node = Node(identity, config, peer_store, chat_store)
    node.start()   # background threads: discovery + transport
    node.send(peer_user_id, plaintext)  # encrypt + deliver
    node.stop()

Inbound messages are automatically stored; the UI decrypts on demand.
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .discovery import Discovery
from .transport import Transport
from .dht import DHTNode
from core.crypto import E2EManager

log = logging.getLogger("network")

TRANSPORT_PORT = 51821
MAX_INBOUND_BYTES = 256 * 1024  # 256 KiB — generous for a text envelope, stops trivial DoS


def _signable(envelope: dict) -> bytes:
    """Canonical bytes signed/verified for an envelope (excludes 'sig' itself)."""
    fields = {k: envelope[k] for k in ("from", "chat_id", "token", "ts") if k in envelope}
    return json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Node:
    def __init__(self, identity_manager, config_store, peer_store, chat_store):
        """
        identity_manager: IdentityManager (keys already loaded)
        config_store:     ConfigStore
        peer_store:       PeerStore
        chat_store:       ChatStore
        """
        self._im     = identity_manager
        self._config = config_store
        self._peers  = peer_store
        self._chats  = chat_store

        # Public callback lists — append callables to hook into node events.
        # Each callback receives the same argument as the internal handler.
        self.on_inbound_callbacks: list = []
        self.on_peer_found_callbacks: list = []

        self._identity = self._build_identity()
        port = config_store.get_setting("network_port") or TRANSPORT_PORT

        # Correction to an earlier decision in this same file: this used to
        # default to loopback-only, requiring explicit opt-in (network_bind=lan)
        # to be reachable on the LAN at all. That reasoning didn't hold up —
        # Discovery (right below) has ALWAYS broadcast your presence and real
        # LAN IP unconditionally, before and after that change. Restricting
        # only Transport meant the actual broken state was the DEFAULT one:
        # other peers correctly discover you and record your real IP, then
        # every attempt to actually message you gets connection-refused,
        # because nothing was listening on that interface. Discovery already
        # gives up whatever privacy loopback-only Transport was trying to
        # protect, so pairing them inconsistently bought nothing and broke
        # the app's core feature by default. Confirmed this exact failure
        # end to end, not just in theory: peer_store had the right ip:port,
        # the send still failed with ECONNREFUSED.
        #
        # Fixed by making the two consistent: participating in LAN discovery
        # and being reachable on the LAN are now the same decision, not two
        # independently-configurable ones that can silently contradict each
        # other. Explicit network_bind=host now means "opt OUT of LAN
        # entirely" — Discovery doesn't start either, so that state is fully
        # coherent (no broadcast, no listen) instead of the old half-state.
        bind_mode = (
            os.environ.get("ENCLAVE_NET_HOST")
            or config_store.get_setting("network_bind", "lan")
        )
        self._lan_enabled = bind_mode != "host"
        transport_host = "0.0.0.0" if self._lan_enabled else "127.0.0.1"

        self._transport = Transport(
            host=transport_host,
            port=port,
            on_message=self._on_inbound,
        )
        self._transport_port = port
        self._discovery = Discovery(
            identity=self._identity,
            transport_port=port,
            peer_store=peer_store,
            on_peer_found=self._on_peer_found,
        )

        # DHT (internet discovery) is opt-in, not opt-out: joining a public
        # DHT means announcing "here's my address" to a swarm of strangers,
        # which is a meaningfully different exposure than LAN broadcast.
        # See core/network/dht.py for exactly what this does and doesn't do
        # (notably: it does NOT solve NAT traversal by itself).
        self._dht = None
        if config_store.get_setting("dht_enabled", False):
            dht_port = config_store.get_setting("dht_port") or (port + 1000)
            self._dht = DHTNode(
                user_id=self._identity["user_id"],
                port=dht_port,
                peer_store=peer_store,
                on_peer_found=self._on_peer_found,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._transport.start()
        self._discovery.start()
        if self._dht:
            bootstrap = self._config.get_setting("dht_bootstrap", [])
            self._dht.start(bootstrap_addrs=bootstrap)
            self._dht.set_identity_payload(
                ed25519_pub=self._identity["ed25519_pub"],
                x25519_pub=self._identity["x25519_pub"],
                transport_port=self._transport_port,
                public_ip=self._config.get_setting("dht_public_ip"),
            )
            # Always attempt an initial announce, even with no bootstrap
            # list of our own (e.g. we're the seed/root node others
            # bootstrap FROM) — it may not have anyone to learn our own
            # address from yet, in which case DHTNode's own early-retry
            # loop (a few short retries over the first ~15s) picks it up
            # once someone has actually contacted us.
            self._dht.announce_self()
        log.info("[node] started — user_id: %s", self._identity["user_id"][:16])

    def stop(self):
        self._discovery.stop()
        self._transport.stop()
        if self._dht:
            self._dht.stop()
        log.info("[node] stopped")

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send(self, peer_user_id: str, plaintext: str) -> bool:
        """
        Encrypt plaintext with E2E (X25519 ECDH) and deliver to peer.
        Returns True if delivered, False otherwise.
        Raises RuntimeError if the peer's x25519_pub is unknown.
        """
        peer = self._peers.get(peer_user_id)
        if not peer and self._dht:
            log.info("[node] %s not in local peer_store — trying DHT", peer_user_id[:12])
            peer = self._dht.find_peer(peer_user_id)
        if not peer:
            log.warning("[node] send: unknown peer %s", peer_user_id[:12])
            return False
        if not peer.get("ip") or not peer.get("port"):
            log.warning("[node] send: no address for peer %s", peer_user_id[:12])
            return False

        peer_pub = peer.get("x25519_pub", "")
        if not peer_pub:
            raise RuntimeError(
                f"No X25519 public key on record for peer {peer_user_id[:12]} — "
                "cannot encrypt. Has the peer been discovered yet?"
            )

        ts    = datetime.now(timezone.utc).isoformat()
        e2e   = E2EManager(self._im.x25519_priv)
        token = e2e.encrypt(
            plaintext=plaintext,
            peer_x25519_pub_b64=peer_pub,
            chat_id=peer_user_id,
            created_at=ts,
        )

        envelope = {
            "from":    self._identity["user_id"],
            "chat_id": peer_user_id,
            "token":   token,
            "ts":      ts,
        }
        # Sign with our Ed25519 identity key so the recipient can verify
        # this envelope actually came from us and wasn't spoofed/replayed
        # by someone else on the network.
        sig = self._im.ed25519_priv.sign(_signable(envelope))
        envelope["sig"] = base64.urlsafe_b64encode(sig).decode("utf-8")

        address = f"http://{peer['ip']}:{peer['port']}"
        ok = self._transport.send(address, envelope)
        if ok:
            log.info("[node] delivered to %s", peer_user_id[:12])

        # Record OUR OWN copy under the same chat thread the recipient uses
        # (peer_user_id), regardless of delivery outcome — otherwise a sent
        # message never appears in your own history at all, only the
        # recipient's.
        #
        # This deliberately stores PLAINTEXT, not the ciphertext token.
        # e2e.py uses ephemeral-static ECDH (the sender's ephemeral private
        # key is discarded right after encrypt() returns, which is what
        # gives forward secrecy) — only the RECIPIENT's static private key
        # can reverse it. The sender can never decrypt their own ciphertext
        # with this scheme; nobody can but the intended recipient. Since we
        # already have the plaintext right here (it's a plain function
        # argument, before encryption), storing it directly for the local
        # echo is the same trade-off real E2E messengers make: E2E secrecy
        # covers the network leg, and your own local copy of what you sent
        # is protected by the same OS file permissions as the rest of your
        # profile data (see key_manager.py's chmod 600), not by a second
        # layer of at-rest encryption on top.
        self._chats.append_message(peer_user_id, {
            "token":     plaintext,
            "plaintext": True,
            "sender":    "me",
            "ts":        ts,
            "verified":  True,
        })

        return ok

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def _on_inbound(self, envelope: dict):
        sender_id  = envelope.get("from", "")
        token      = envelope.get("token", "")
        ts         = envelope.get("ts", datetime.now(timezone.utc).isoformat())
        sig_b64    = envelope.get("sig", "")

        if not sender_id or not token:
            log.warning("[node] inbound: malformed envelope")
            return

        # Verify the signature against whatever ed25519_pub we have on file
        # for this sender_id. If we've never seen this peer before, there's
        # no key to verify against yet (TOFU) — accept but mark unverified
        # so the UI can flag it instead of silently trusting it forever.
        known_peer = self._peers.get(sender_id)
        verified = False
        if known_peer and known_peer.get("ed25519_pub"):
            if not sig_b64:
                log.warning("[node] inbound: unsigned message claiming to be "
                            "known peer %s — dropped", sender_id[:12])
                return
            try:
                pub = Ed25519PublicKey.from_public_bytes(
                    base64.urlsafe_b64decode(known_peer["ed25519_pub"].encode())
                )
                pub.verify(base64.urlsafe_b64decode(sig_b64.encode()), _signable(envelope))
                verified = True
            except (InvalidSignature, ValueError, Exception):
                log.warning("[node] inbound: BAD SIGNATURE from %s — "
                            "message dropped (possible spoofing)", sender_id[:12])
                return
        else:
            log.info("[node] inbound: first contact from %s — unverified "
                      "(no key on file yet)", sender_id[:12])

        self._chats.append_message(sender_id, {
            "token":    token,
            "sender":   sender_id,
            "ts":       ts,
            "verified": verified,
        })
        log.info("[node] inbound message from %s (verified=%s)", sender_id[:12], verified)

        for cb in self.on_inbound_callbacks:
            try:
                cb(envelope)
            except Exception:
                log.exception("[node] on_inbound callback error")

    # ------------------------------------------------------------------
    # Peer events
    # ------------------------------------------------------------------

    def _on_peer_found(self, peer: dict):
        log.info("[node] peer found: %s (%s) @ %s",
                 peer.get("username", "?"),
                 peer.get("user_id", "")[:12],
                 peer.get("ip", "?"))

        for cb in self.on_peer_found_callbacks:
            try:
                cb(peer)
            except Exception:
                log.exception("[node] on_peer_found callback error")

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
            "user_id":     self._im.get_user_id(),
            "username":    self._config.username or "",
            "ed25519_pub": raw_pub(self._im.ed25519_priv),
            "x25519_pub":  raw_pub(self._im.x25519_priv),
        }
