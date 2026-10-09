"""
key_store.py — Per-chat key storage.
Each chat's prekey is stored as storage/keys/<chat_id>.key
"""

import os


class KeyStore:
    def __init__(self, base_dir="storage"):
        self.keys_dir = os.path.join(base_dir, "keys")
        os.makedirs(self.keys_dir, exist_ok=True)

    def _path(self, chat_id: str) -> str:
        safe = chat_id.replace("/", "_").replace("\\", "_")
        return os.path.join(self.keys_dir, f"{safe}.key")

    def save_key(self, chat_id: str, prekey: str):
        """Save a prekey for a given chat ID."""
        with open(self._path(chat_id), "w", encoding="utf-8") as f:
            f.write(prekey)

    def load_key(self, chat_id: str) -> str | None:
        """Load the prekey for a given chat ID. Returns None if not found."""
        path = self._path(chat_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()

    def delete_key(self, chat_id: str) -> bool:
        """Delete the prekey for a given chat ID."""
        path = self._path(chat_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def has_key(self, chat_id: str) -> bool:
        return os.path.exists(self._path(chat_id))

    def list_chats(self) -> list[str]:
        """Return all chat IDs that have stored keys."""
        return [
            f[:-4] for f in os.listdir(self.keys_dir)
            if f.endswith(".key")
        ]
