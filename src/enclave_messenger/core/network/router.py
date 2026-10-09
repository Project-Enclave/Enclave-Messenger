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
from .contacts import ContactManager
from .relay import RelayManager
from enclave_messenger.core.crypto import E2EManager
from enclave_messenger.core.storage.relay_store import RelayStore

log = logging.getLogger("network")

TRANSPORT_PORT = 51821
MAX_INBOUND_BYTES = 256 * 1024  # 256 KiB — generous for a text envelope, stops trivial DoS


_SIGNABLE_FIELDS = (
    "from", "chat_id", "token", "ts",
    # Only ever present on contact_request/contact_accept envelopes (see
    # Node.request_contact()/accept_contact()) — regular message envelopes
    # never carry these, so including them here changes nothing for the
    # existing message-signing path (the dict comprehension below only
    # pulls in keys that are actually present). They MUST be covered,
    # though: without this, an on-path attacker could leave "from" and
    # "sig" untouched but swap "x25519_pub" for their own key — the
    # signature would still verify, and the recipient would end up
    # encrypting future messages to the attacker instead of the real
    # sender. Same class of attack discovery.py's key-pinning already
    # defends against for the LAN broadcast path; this closes the same
    # gap for the contact-request path.
    "type", "username", "ed25519_pub", "x25519_pub",
)


def _signable(envelope: dict) -> bytes:
    """Canonical bytes signed/verified for an envelope (excludes 'sig' itself)."""
    fields = {k: envelope[k] for k in _SIGNABLE_FIELDS if k in envelope}
    return json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Node:
    def __init__(self, identity_manager, config_store, peer_store, chat_store,
                 base_dir: str = None):
        """
        identity_manager: IdentityManager (keys already loaded)
        config_store:     ConfigStore
        peer_store:       PeerStore
        chat_store:       ChatStore
        base_dir:         where this profile's storage/ lives — used for
            contacts.json and relay_queue.json. Optional and derived from
            peer_store's own path when omitted, so existing callers that
            construct Node with just the first four positional args (the
            security test suite included) keep working unchanged.
        """
        self._im     = identity_manager
        self._config = config_store
        self._peers  = peer_store
        self._chats  = chat_store

        if base_dir is None:
            base_dir = os.path.dirname(peer_store._path) or "storage"
        self._contacts    = ContactManager(base_dir=base_dir)
        self._relay_store = RelayStore(
            base_dir=base_dir,
            ttl_hours=config_store.get("relay", {}).get("ttl_hours", 48),
            max_total_bytes=config_store.get("relay", {}).get("max_total_mb", 20) * 1024 * 1024,
        )

        # Public callback lists — append callables to hook into node events.
        # Each callback receives the same argument as the internal handler.
        self.on_inbound_callbacks: list = []
        self.on_peer_found_callbacks: list = []
        self.on_contact_request_callbacks: list = []

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
            # Serves GET /identity so another node can resolve a manual
            # ip:port into a real identity. Only public material — exactly
            # what discovery already broadcasts over the LAN anyway.
            identity_provider=lambda: dict(self._identity),
            on_relay=self._on_relay_inbound,
        )
        self._transport_port = port
        self._discovery = Discovery(
            identity=self._identity,
            transport_port=port,
            peer_store=peer_store,
            on_peer_found=self._on_peer_found,
        )

        # Store-and-forward: flush anything queued for a peer the moment
        # they're seen online, whether that's via LAN discovery, DHT, or
        # a manual connect_to_address() — all three already funnel through
        # _on_peer_found below, so registering once here covers all of them.
        self._relay_mgr = RelayManager(self._relay_store, self._transport, peer_store)
        self.on_peer_found_callbacks.append(self._relay_mgr.on_peer_found)

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
        if self._lan_enabled:
            self._discovery.start()
        else:
            # Without this, network_bind=host produced the exact incoherent
            # half-state the bind_mode fix above exists to prevent, just
            # inverted: Discovery still broadcasts your presence and real
            # LAN IP to everyone, while Transport listens on loopback only,
            # so every peer that discovers you gets connection-refused when
            # they try to reach you. Opting out of LAN has to mean opting
            # out of both halves, or it isn't opting out of anything.
            log.info("[node] LAN discovery disabled (network_bind=host) — "
                      "not broadcasting or listening for LAN peers")
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
        # Discovery.stop() joins its two threads unconditionally, which
        # would raise if they were never started — so this has to mirror
        # the guard in start() exactly.
        if self._lan_enabled:
            self._discovery.stop()
        self._transport.stop()
        if self._dht:
            self._dht.stop()
        log.info("[node] stopped")

    # ------------------------------------------------------------------
    # Manual connect (ip:port)
    # ------------------------------------------------------------------

    def connect_to_address(self, address: str) -> dict | None:
        """
        Add a peer by raw "ip:port" — for when discovery can't reach them
        (different subnet, multicast blocked by the network, a VPS, a
        device you know the address of but which never showed up in
        discovery).

        Asks that address who it is via GET /identity, then stores the
        answer. Returns the peer dict, or None if nothing enclave-shaped
        answered.

        Key pinning is identical to discovery.py's: if we already know
        this user_id with DIFFERENT keys, the new keys are refused rather
        than silently overwriting a trusted mapping. Being typed in by
        hand doesn't make an address more trustworthy than a broadcast —
        someone can just as easily give you the wrong one — so the same
        rule applies. Only the ADDRESS is updated for an already-known
        peer, which is the legitimate use (peer moved, same identity).
        """
        address = (address or "").strip()
        if address.startswith("http://"):
            address = address[len("http://"):]
        host, _, port_s = address.partition(":")
        if not host or not port_s.isdigit():
            raise ValueError("expected ip:port, e.g. 192.168.0.102:43110")
        port = int(port_s)

        info = self._transport.fetch_identity(f"http://{host}:{port}")
        if not info:
            return None

        peer_id = info["user_id"]
        if peer_id == self._identity["user_id"]:
            raise ValueError("that address is this node itself")

        new_ed, new_x = info["ed25519_pub"], info["x25519_pub"]
        existing = self._peers.get(peer_id)
        if existing and existing.get("ed25519_pub") and existing.get("x25519_pub"):
            if new_ed != existing["ed25519_pub"] or new_x != existing["x25519_pub"]:
                log.warning(
                    "[node] KEY CHANGE for known peer %s at manually-entered "
                    "address %s — refusing (possible impersonation). Delete "
                    "and re-add the contact if this is expected.",
                    peer_id[:12], address,
                )
                raise ValueError(
                    "that address claims to be a contact you already have, "
                    "but with different keys — refusing to overwrite them"
                )

        # The node's own advertised transport port wins over the port we
        # happened to dial, so a peer reachable via a forwarded/proxied
        # port still records the port it actually listens on.
        peer = self._peers.upsert(
            user_id=peer_id,
            username=info.get("username", ""),
            ed25519_pub=new_ed,
            x25519_pub=new_x,
            ip=host,
            port=info.get("port") or port,
            relay=bool(info.get("relay", False)),
            status=info.get("status", ""),
            bio=info.get("bio", ""),
        )
        log.info("[node] connected to %s via manual address %s", peer_id[:12], address)
        self._on_peer_found(peer)
        return peer

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
            self._record_failed(peer_user_id, plaintext)
            return False
        if not peer.get("ip") or not peer.get("port"):
            log.warning("[node] send: no address for peer %s", peer_user_id[:12])
            self._record_failed(peer_user_id, plaintext)
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

        via = self._deliver_via(peer_user_id, envelope, peer)
        ok = via is not None

        # First-contact bookkeeping: if we've never talked to this peer
        # before (no contact record either way), sending them a message
        # is US initiating — mark it so, purely for our own UI ("pending"
        # indicator on our side). Does NOT affect delivery, and does
        # nothing at all if we already have any status recorded, so an
        # already-accepted contact is untouched every time you message
        # them (this only ever fires once, on the very first send).
        if self._contacts.get_status(peer_user_id) is None:
            self._contacts.mark_pending_outgoing(peer_user_id, username=peer.get("username", ""))

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
            "status":    self._status_for(via),
            "via":       via or "",
        })

        return ok

    # ------------------------------------------------------------------
    # Delivery (direct, falling back to a relay)
    # ------------------------------------------------------------------

    def _deliver(self, peer_user_id: str, envelope: dict, peer: dict) -> bool:
        return self._deliver_via(peer_user_id, envelope, peer) is not None

    def _deliver_via(self, peer_user_id: str, envelope: dict, peer: dict):
        """
        Try direct delivery first; if that fails (peer offline/
        unreachable) and we know of any peer who has advertised relay
        capability (see discovery.py's "relay" field), hand the envelope
        off to one instead. A relay hand-off still counts as sent: as far
        as the sender is concerned the message has left their device
        successfully, same as SMS/email — "sent", not "read". The relay
        never sees plaintext (see core/network/relay.py's module docstring).

        Returns "direct", "relay", or None if nothing worked, so the UI can
        tell "reached them" apart from "parked with a relay" and "failed".
        """
        address = f"http://{peer['ip']}:{peer['port']}"
        if self._transport.send(address, envelope):
            log.info("[node] delivered to %s", peer_user_id[:12])
            return "direct"

        relay_candidates = [
            p for p in self._peers.all()
            if p.get("relay") and p.get("user_id") != peer_user_id
            and p.get("ip") and p.get("port")
        ]
        for relay in relay_candidates:
            relay_address = f"http://{relay['ip']}:{relay['port']}"
            if self._transport.send_relay(relay_address, envelope):
                log.info("[node] %s unreachable — handed off to relay %s",
                          peer_user_id[:12], relay["user_id"][:12])
                return "relay"

        log.warning("[node] delivery to %s failed (direct and %d relay "
                     "candidate(s) all failed or none available)",
                     peer_user_id[:12], len(relay_candidates))
        return None

    def _record_failed(self, peer_user_id: str, plaintext: str) -> None:
        """Keep what the user typed visible (with a retry button) even when
        we could not attempt delivery at all — otherwise it just vanishes."""
        self._chats.append_message(peer_user_id, {
            "token":     plaintext,
            "plaintext": True,
            "sender":    "me",
            "ts":        datetime.now(timezone.utc).isoformat(),
            "verified":  True,
            "status":    "failed",
            "via":       "",
        })

    @staticmethod
    def _status_for(via):
        if via == "direct":
            return "delivered"
        if via == "relay":
            return "relayed"
        return "failed"

    def retry_message(self, peer_user_id: str, ts: str) -> bool:
        """
        Re-send a previously FAILED outgoing message (same text, same
        timestamp) and update its stored status in place — no duplicate
        bubble. Returns True if it is no longer failed.
        """
        rec = next((m for m in self._chats.load_messages(peer_user_id)
                    if m.get("ts") == ts and m.get("sender") == "me"), None)
        if rec is None or rec.get("status") != "failed" or not rec.get("plaintext"):
            return False
        peer = self._peers.get(peer_user_id)
        if not peer and self._dht:
            peer = self._dht.find_peer(peer_user_id)
        if not peer or not peer.get("ip") or not peer.get("port"):
            return False
        peer_pub = peer.get("x25519_pub", "")
        if not peer_pub:
            return False

        token = E2EManager(self._im.x25519_priv).encrypt(
            plaintext=rec["token"],
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
        sig = self._im.ed25519_priv.sign(_signable(envelope))
        envelope["sig"] = base64.urlsafe_b64encode(sig).decode("utf-8")

        via = self._deliver_via(peer_user_id, envelope, peer)
        self._chats.update_message(peer_user_id, ts,
                                   status=self._status_for(via), via=via or "")
        return via is not None

    def _on_relay_inbound(self, envelope: dict) -> tuple[bool, str]:
        """
        Called by Transport for POST /relay — someone is asking THIS
        node to hold an envelope on behalf of a third party. Returns
        (accepted, reason).
        """
        if not self._identity.get("relay", False):
            return False, "relay not enabled on this node"
        chat_id = envelope.get("chat_id", "")
        if not chat_id or chat_id == self._identity["user_id"]:
            return False, "invalid relay target"
        ok, reason = self._relay_store.enqueue(chat_id, envelope)
        if ok:
            log.info("[node] relay: queued envelope for %s", chat_id[:12])
            # Opportunistic: if we already know this peer's address (they
            # might be online right now, just not reachable from the
            # original sender — different subnet, etc.), try immediately
            # instead of waiting for the next time discovery sees them.
            if self._peers.get(chat_id):
                self._relay_mgr.flush_for(chat_id)
        return ok, reason

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def _on_inbound(self, envelope: dict):
        etype = envelope.get("type", "message")
        if etype == "contact_request":
            self._handle_contact_request(envelope)
            return
        if etype == "contact_accept":
            self._handle_contact_accept(envelope)
            return

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

        # Contact/consent gating (see core/network/contacts.py). This is
        # layered ON TOP of the signature/TOFU check above, not instead of
        # it — a message still has to pass identity verification before we
        # even ask whether we've agreed to hear from this identity.
        status = self._contacts.get_status(sender_id)
        pending_contact = False
        if status == "blocked":
            log.info("[node] inbound: message from blocked contact %s dropped",
                      sender_id[:12])
            return
        if status == "pending_outgoing":
            # We messaged/requested THEM first, and this is a real message
            # back — that only happens if they've accepted (their side
            # gates outbound sends the same way), so treat it as mutual
            # acceptance without waiting for a contact_accept envelope
            # that a flaky connection might have dropped.
            self._contacts.mark_accepted(sender_id)
        elif status != "accepted":
            # No relationship yet, or they messaged us before we acted on
            # their request — store it, but flag it as a pending contact
            # request rather than a normal conversation message.
            self._contacts.mark_pending_incoming(
                sender_id, username=(known_peer or {}).get("username", ""))
            pending_contact = True

        self._chats.append_message(sender_id, {
            "token":    token,
            "sender":   sender_id,
            "ts":       ts,
            "verified": verified,
            "pending_contact": pending_contact,
        })
        log.info("[node] inbound message from %s (verified=%s, pending_contact=%s)",
                  sender_id[:12], verified, pending_contact)

        for cb in self.on_inbound_callbacks:
            try:
                cb(envelope)
            except Exception:
                log.exception("[node] on_inbound callback error")

    def _handle_contact_request(self, envelope: dict):
        """
        Someone we may never have discovered is asking to start a
        conversation. The envelope is self-certifying: it carries the
        sender's own ed25519/x25519 public keys, and we verify (a) the
        signature against the embedded ed25519 key and (b) that the
        claimed user_id is actually DERIVED from that same key (same
        derivation IdentityManager.get_user_id() uses) — so accepting it
        doesn't require having seen this identity before at all, unlike
        a bare TOFU message.
        """
        sender_id = envelope.get("from", "")
        ed_pub    = envelope.get("ed25519_pub", "")
        x_pub     = envelope.get("x25519_pub", "")
        sig_b64   = envelope.get("sig", "")
        if not sender_id or not ed_pub or not x_pub or not sig_b64:
            log.warning("[node] contact_request: malformed envelope — dropped")
            return

        try:
            raw = base64.urlsafe_b64decode(ed_pub.encode())
            derived_id = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
            if derived_id != sender_id.rstrip("="):
                log.warning("[node] contact_request: claimed user_id doesn't "
                            "match embedded key — dropped")
                return
            pub = Ed25519PublicKey.from_public_bytes(raw)
            pub.verify(base64.urlsafe_b64decode(sig_b64.encode()), _signable(envelope))
        except (InvalidSignature, ValueError, Exception):
            log.warning("[node] contact_request: bad signature from %s — dropped",
                         sender_id[:12])
            return

        if self._contacts.get_status(sender_id) == "blocked":
            log.info("[node] contact_request from blocked peer %s ignored",
                      sender_id[:12])
            return

        # Learn their keys now if discovery hasn't already — same trust
        # level discovery itself operates at (self-reported, TOFU-pinned
        # from here on). We deliberately don't have ip/port to record: this
        # arrived over HTTP with no reliable source address in the
        # envelope itself, and discovery will fill that in on its own if/
        # when it also sees them on the LAN.
        existing = self._peers.get(sender_id)
        if not existing or not existing.get("x25519_pub"):
            self._peers.upsert(user_id=sender_id, username=envelope.get("username", ""),
                                ed25519_pub=ed_pub, x25519_pub=x_pub)

        self._contacts.mark_pending_incoming(
            sender_id,
            username=envelope.get("username", ""),
            greeting=envelope.get("token", ""),
        )
        log.info("[node] contact request from %s", sender_id[:12])
        for cb in self.on_contact_request_callbacks:
            try:
                cb({
                    "peer_id":  sender_id,
                    "username": envelope.get("username", ""),
                    "greeting": envelope.get("token", ""),
                })
            except Exception:
                log.exception("[node] on_contact_request callback error")

    def _handle_contact_accept(self, envelope: dict):
        """The other side accepted a request WE sent — flips our local
        status from pending_outgoing to accepted without the user having
        to do anything (a message from them would eventually do the same
        thing, but this makes it immediate)."""
        sender_id = envelope.get("from", "")
        sig_b64   = envelope.get("sig", "")
        if not sender_id or not sig_b64:
            return
        known_peer = self._peers.get(sender_id)
        pub_b64 = (known_peer or {}).get("ed25519_pub") or envelope.get("ed25519_pub", "")
        if not pub_b64:
            return
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(pub_b64.encode()))
            pub.verify(base64.urlsafe_b64decode(sig_b64.encode()), _signable(envelope))
        except (InvalidSignature, ValueError, Exception):
            log.warning("[node] contact_accept: bad signature from %s — dropped",
                         sender_id[:12])
            return
        self._contacts.mark_accepted(sender_id)
        log.info("[node] contact request accepted by %s", sender_id[:12])

    # ------------------------------------------------------------------
    # Contacts (handshake) — public API used by main.py
    # ------------------------------------------------------------------

    def request_contact(self, peer_user_id: str, greeting: str = "") -> bool:
        """Explicitly send a contact request (optionally with a greeting)
        without sending a real message yet. Not required — a first real
        send() does the same first-contact bookkeeping — but useful for
        an explicit "add contact" UI flow with no message content."""
        peer = self._peers.get(peer_user_id)
        if not peer or not peer.get("ip") or not peer.get("port"):
            return False
        ts = datetime.now(timezone.utc).isoformat()
        envelope = {
            "type":        "contact_request",
            "from":        self._identity["user_id"],
            "chat_id":     peer_user_id,
            "token":       greeting,
            "ts":          ts,
            "username":    self._identity.get("username", ""),
            "ed25519_pub": self._identity["ed25519_pub"],
            "x25519_pub":  self._identity["x25519_pub"],
        }
        sig = self._im.ed25519_priv.sign(_signable(envelope))
        envelope["sig"] = base64.urlsafe_b64encode(sig).decode("utf-8")
        ok = self._deliver(peer_user_id, envelope, peer)
        self._contacts.mark_pending_outgoing(peer_user_id, username=peer.get("username", ""))
        return ok

    def accept_contact(self, peer_user_id: str) -> bool:
        self._contacts.mark_accepted(peer_user_id)
        self._chats.clear_pending_contact(peer_user_id)

        peer = self._peers.get(peer_user_id)
        if not peer or not peer.get("ip") or not peer.get("port"):
            return True  # accepted locally even if we can't notify them yet

        ts = datetime.now(timezone.utc).isoformat()
        envelope = {
            "type":        "contact_accept",
            "from":        self._identity["user_id"],
            "chat_id":     peer_user_id,
            "token":       "",
            "ts":          ts,
            "ed25519_pub": self._identity["ed25519_pub"],
            "x25519_pub":  self._identity["x25519_pub"],
        }
        sig = self._im.ed25519_priv.sign(_signable(envelope))
        envelope["sig"] = base64.urlsafe_b64encode(sig).decode("utf-8")
        return self._deliver(peer_user_id, envelope, peer)

    def reject_contact(self, peer_user_id: str) -> None:
        """Blocks the peer locally. Deliberately silent — no envelope is
        sent back — same as most messengers' "decline" behaviour: it
        doesn't confirm to the other side that they were specifically
        rejected (vs. simply not yet answered)."""
        self._contacts.mark_blocked(peer_user_id)

    def pending_contact_requests(self) -> list:
        return self._contacts.pending_incoming()

    def contact_status(self, peer_user_id: str) -> str | None:
        return self._contacts.get_status(peer_user_id)

    # ------------------------------------------------------------------
    # Profile customization — public API used by main.py
    # ------------------------------------------------------------------

    def set_status(self, text: str):
        self._config.set_profile(status=text)
        self._identity["status"] = text  # picked up by Discovery's next announce

    def set_bio(self, text: str):
        self._config.set_profile(bio=text)
        self._identity["bio"] = text

    def set_relay_enabled(self, enabled: bool):
        self._config.set_relay_config(enabled=enabled)
        self._identity["relay"] = bool(enabled)
        if enabled:
            # Catch up on anything already queued from before this node
            # last enabled relay (e.g. it was toggled off and back on).
            self._relay_mgr.flush_all()

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

        profile = self._config.get("profile", {}) or {}
        relay_cfg = self._config.get("relay", {}) or {}
        return {
            "user_id":     self._im.get_user_id(),
            "username":    self._config.username or "",
            "ed25519_pub": raw_pub(self._im.ed25519_priv),
            "x25519_pub":  raw_pub(self._im.x25519_priv),
            # Mutated in place later by set_status()/set_bio()/
            # set_relay_enabled() — Discovery holds this SAME dict by
            # reference, so a change here is picked up on its next
            # announce without any extra plumbing.
            "status":      profile.get("status", ""),
            "bio":         profile.get("bio", ""),
            "relay":       bool(relay_cfg.get("enabled", False)),
        }
