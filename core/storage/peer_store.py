"""
peer_store.py — Stores known peers and their public keys.

Each peer entry:
  {
    "user_id":    str,   # base64url Ed25519 public key (also the unique ID)
    "username":   str,   # display name, self-reported
    "ed25519_pub": str,  # base64url raw Ed25519 public key bytes
    "x25519_pub":  str,  # base64url raw X25519 public key bytes
    "ip":         str,   # last known LAN IP
    "port":       int,   # transport listen port
    "last_seen":  str,   # ISO-8601 timestamp
  }

Persisted to storage/peers.json.
"""

import json
import os
from datetime import datetime, timezone


PEERS_FILE = os.path.join("storage", "peers.json")


class PeerStore:
    def __init__(self, base_dir: str = "storage"):
        self._path = os.path.join(base_dir, "peers.json")
        os.makedirs(base_dir, exist_ok=True)
        self._peers: dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # keyed by user_id
                self._peers = {p["user_id"]: p for p in data if "user_id" in p}
            except (json.JSONDecodeError, KeyError):
                self._peers = {}

    def _save(self):
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(list(self._peers.values()), f, indent=2)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upsert(self, user_id: str, *, username: str = "",
               ed25519_pub: str = "", x25519_pub: str = "",
               ip: str = "", port: int = 0) -> dict:
        """Insert or update a peer. Returns the stored entry."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self._peers.get(user_id, {})
        entry = {
            "user_id":     user_id,
            "username":    username   or existing.get("username", ""),
            "ed25519_pub": ed25519_pub or existing.get("ed25519_pub", ""),
            "x25519_pub":  x25519_pub  or existing.get("x25519_pub", ""),
            "ip":          ip          or existing.get("ip", ""),
            "port":        port        or existing.get("port", 0),
            "last_seen":   now,
        }
        self._peers[user_id] = entry
        self._save()
        return entry

    def get(self, user_id: str) -> dict | None:
        return self._peers.get(user_id)

    def all(self) -> list[dict]:
        return list(self._peers.values())

    def remove(self, user_id: str) -> bool:
        if user_id in self._peers:
            del self._peers[user_id]
            self._save()
            return True
        return False

    def has(self, user_id: str) -> bool:
        return user_id in self._peers

    def update_address(self, user_id: str, ip: str, port: int):
        """Quick update of just the IP/port + last_seen for a known peer."""
        if user_id in self._peers:
            self._peers[user_id]["ip"] = ip
            self._peers[user_id]["port"] = port
            self._peers[user_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
            self._save()
