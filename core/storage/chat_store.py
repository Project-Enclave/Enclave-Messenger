"""
chat_store.py — Per-chat encrypted message storage.
Each chat is stored as storage/chats/<chat_id>.enc
Messages are stored as newline-delimited encrypted tokens.
"""

import os


class ChatStore:
    def __init__(self, base_dir="storage"):
        self.chats_dir = os.path.join(base_dir, "chats")
        os.makedirs(self.chats_dir, exist_ok=True)

    def _path(self, chat_id: str) -> str:
        safe = chat_id.replace("/", "_").replace("\\", "_")
        return os.path.join(self.chats_dir, f"{safe}.enc")

    def append_message(self, chat_id: str, token: str):
        """Append an encrypted token to the chat file."""
        with open(self._path(chat_id), "a", encoding="utf-8") as f:
            f.write(token.strip() + "\n")

    def load_messages(self, chat_id: str) -> list[str]:
        """Load all encrypted tokens for a chat. Returns [] if not found."""
        path = self._path(chat_id)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def delete_chat(self, chat_id: str) -> bool:
        """Delete all messages for a chat."""
        path = self._path(chat_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def has_chat(self, chat_id: str) -> bool:
        return os.path.exists(self._path(chat_id))

    def list_chats(self) -> list[str]:
        """Return all chat IDs that have stored messages."""
        return [
            f[:-4] for f in os.listdir(self.chats_dir)
            if f.endswith(".enc")
        ]

    def message_count(self, chat_id: str) -> int:
        return len(self.load_messages(chat_id))
