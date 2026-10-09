"""
relay.py — RelayManager: delivers store-and-forward envelopes this node
is holding on behalf of OTHER peers, once those peers are seen online.

This node never decrypts or otherwise needs to understand what it
relays. It only ever looks at an envelope's "chat_id" field (the
intended recipient) to know who to hand it to — the actual delivery is
a re-POST of the exact same bytes to that recipient's own /inbound, via
the normal Transport.send(), exactly as if this node were the original
sender. The signature inside the envelope was made by the ORIGINAL
sender and is never touched here, so the recipient's existing
signature verification (see router.py's _on_inbound) verifies it
against the real sender's key, not this relay's — the relay is
cryptographically invisible to that check, by design.
"""

import logging

log = logging.getLogger("network")


class RelayManager:
    def __init__(self, relay_store, transport, peer_store):
        self._store = relay_store
        self._transport = transport
        self._peers = peer_store

    def flush_for(self, peer_id: str) -> int:
        """
        Attempt delivery of everything queued for peer_id. Returns the
        number of envelopes successfully delivered (and removed from the
        queue). Whatever fails to deliver stays queued for the next
        attempt (next time this peer is seen online, or the next
        opportunistic flush).
        """
        peer = self._peers.get(peer_id)
        if not peer or not peer.get("ip") or not peer.get("port"):
            return 0
        pending = self._store.pending_for(peer_id)
        if not pending:
            return 0

        address = f"http://{peer['ip']}:{peer['port']}"
        delivered = 0
        still_pending = []
        for entry in pending:
            envelope = {k: v for k, v in entry.items() if k != "_queued_at"}
            if self._transport.send(address, envelope):
                delivered += 1
            else:
                still_pending.append(entry)

        if delivered:
            log.info("[relay] delivered %d queued envelope(s) to %s",
                      delivered, peer_id[:12])
        self._store.replace_for(peer_id, still_pending)
        return delivered

    def flush_all(self) -> int:
        """Attempt delivery for every peer currently holding something in
        the queue. Useful right after enabling relay mode, or on a timer,
        in case a peer came and went while this node itself was offline."""
        total = 0
        for peer_id in self._store.pending_peer_ids():
            total += self.flush_for(peer_id)
        return total

    def on_peer_found(self, peer: dict):
        """Hook for Node.on_peer_found_callbacks — opportunistically
        flushes anything queued for a peer the moment discovery (or a
        manual connect) sees them come online."""
        peer_id = peer.get("user_id", "")
        if peer_id:
            self.flush_for(peer_id)
