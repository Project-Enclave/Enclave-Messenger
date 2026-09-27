"""
contacts.py — Contact acceptance state: who you've agreed to actually
exchange messages with.

Discovery and inbound signature checking (see discovery.py and
router.py) already establish CRYPTOGRAPHIC identity — TOFU-pinned keys,
so a peer can't silently swap out their key later. That part is
unchanged by this module. What was missing entirely is CONSENT: with no
contact layer, the very first envelope from a total stranger was stored
and displayed exactly like a message from someone you trust, and there
was no way to say "I don't want to hear from this person" short of
never opening the app. ContactManager adds that layer on top of the
existing crypto, without touching it.

Status values, per peer_id:
  "pending_outgoing"  we messaged/requested them, awaiting their reply
  "pending_incoming"  they messaged/requested us, awaiting our accept/reject
  "accepted"          full contact — messages display normally
  "blocked"           we rejected them; further contact attempts are dropped

No entry at all (get_status() returns None) means "never interacted" —
kept distinct from "blocked" so a first message from someone new is
treated as a request, not silently dropped.

Persisted to storage/contacts.json.
"""

import json
import os
from datetime import datetime, timezone


class ContactManager:
    def __init__(self, base_dir: str = "storage"):
        self._path = os.path.join(base_dir, "contacts.json")
        os.makedirs(base_dir, exist_ok=True)
        self._contacts: dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._contacts = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._contacts = {}

    def _save(self):
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._contacts, f, indent=2)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def has(self, peer_id: str) -> bool:
        return peer_id in self._contacts

    def get_status(self, peer_id: str) -> str | None:
        entry = self._contacts.get(peer_id)
        return entry["status"] if entry else None

    def get(self, peer_id: str) -> dict | None:
        return self._contacts.get(peer_id)

    def mark_pending_outgoing(self, peer_id: str, username: str = ""):
        existing = self._contacts.get(peer_id, {})
        if existing.get("status") == "accepted":
            return  # never downgrade an already-accepted contact
        self._contacts[peer_id] = {
            "status":   "pending_outgoing",
            "username": username or existing.get("username", ""),
            "greeting": existing.get("greeting", ""),
            "ts":       self._now(),
        }
        self._save()

    def mark_pending_incoming(self, peer_id: str, username: str = "", greeting: str = ""):
        existing = self._contacts.get(peer_id, {})
        if existing.get("status") in ("accepted", "blocked"):
            return
        self._contacts[peer_id] = {
            "status":   "pending_incoming",
            "username": username or existing.get("username", ""),
            "greeting": greeting or existing.get("greeting", ""),
            "ts":       self._now(),
        }
        self._save()

    def mark_accepted(self, peer_id: str):
        existing = dict(self._contacts.get(peer_id, {}))
        existing["status"] = "accepted"
        existing["ts"] = self._now()
        self._contacts[peer_id] = existing
        self._save()

    def mark_blocked(self, peer_id: str):
        existing = dict(self._contacts.get(peer_id, {}))
        existing["status"] = "blocked"
        existing["ts"] = self._now()
        self._contacts[peer_id] = existing
        self._save()

    def pending_incoming(self) -> list[dict]:
        return [
            {"peer_id": pid, **entry}
            for pid, entry in self._contacts.items()
            if entry.get("status") == "pending_incoming"
        ]

    def all(self) -> dict:
        return dict(self._contacts)
