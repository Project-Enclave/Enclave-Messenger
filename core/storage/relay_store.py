"""
relay_store.py — Store-and-forward queue for envelopes this node has
agreed to hold on behalf of OTHER peers (relay mode), keyed by the
intended recipient's user_id.

This node can never read anything it stores here: entries are the same
opaque, already end-to-end-encrypted-and-signed envelopes that flow
over POST /inbound everywhere else in the app (see core/network/
transport.py and router.py's Node.send()) — relaying never touches
plaintext, only stores and later re-POSTs the same bytes.

Persisted to storage/relay_queue.json.
"""

import json
import os
import time

DEFAULT_TTL_HOURS = 48
DEFAULT_MAX_PER_PEER = 200
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024  # 20 MiB


class RelayStore:
    def __init__(self, base_dir: str = "storage",
                 ttl_hours: float = DEFAULT_TTL_HOURS,
                 max_per_peer: int = DEFAULT_MAX_PER_PEER,
                 max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES):
        self._path = os.path.join(base_dir, "relay_queue.json")
        os.makedirs(base_dir, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.max_per_peer = max_per_peer
        self.max_total_bytes = max_total_bytes
        self._queues: dict[str, list[dict]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._queues = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._queues = {}

    def _save(self):
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._queues, f)

    def _prune_expired(self):
        cutoff = time.time() - self.ttl_hours * 3600
        changed = False
        for peer_id in list(self._queues.keys()):
            kept = [e for e in self._queues[peer_id] if e.get("_queued_at", 0) >= cutoff]
            if len(kept) != len(self._queues[peer_id]):
                changed = True
            if kept:
                self._queues[peer_id] = kept
            else:
                del self._queues[peer_id]
        if changed:
            self._save()

    def _total_bytes(self) -> int:
        return sum(len(json.dumps(e)) for q in self._queues.values() for e in q)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(self, peer_id: str, envelope: dict) -> tuple[bool, str]:
        """Queue envelope for later delivery to peer_id. Returns
        (accepted, reason) — reason is only meaningful when not accepted,
        so a caller can tell the sender why (capacity, not size)."""
        self._prune_expired()
        q = self._queues.setdefault(peer_id, [])
        if len(q) >= self.max_per_peer:
            return False, f"relay queue full for this recipient (max {self.max_per_peer})"
        size = len(json.dumps(envelope))
        if self._total_bytes() + size > self.max_total_bytes:
            return False, "relay storage capacity reached"
        entry = dict(envelope)
        entry["_queued_at"] = time.time()
        q.append(entry)
        self._save()
        return True, ""

    def pending_for(self, peer_id: str) -> list[dict]:
        self._prune_expired()
        return list(self._queues.get(peer_id, []))

    def clear_for(self, peer_id: str):
        if peer_id in self._queues:
            del self._queues[peer_id]
            self._save()

    def replace_for(self, peer_id: str, remaining: list[dict]):
        """Used after a partial flush — some envelopes delivered, some
        still pending (recipient dropped offline mid-flush, say)."""
        if remaining:
            self._queues[peer_id] = remaining
        elif peer_id in self._queues:
            del self._queues[peer_id]
        self._save()

    def pending_peer_ids(self) -> list[str]:
        self._prune_expired()
        return list(self._queues.keys())

    def stats(self) -> dict:
        self._prune_expired()
        return {
            "queued_recipients": len(self._queues),
            "queued_envelopes": sum(len(q) for q in self._queues.values()),
            "total_bytes": self._total_bytes(),
        }
