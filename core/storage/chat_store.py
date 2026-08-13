"""
chat_store.py — Per-chat message storage.
Each chat is a newline-delimited JSON file: storage/chats/<chat_id>.jsonl
Falls back to reading legacy .enc (plain token strings) transparently.
"""

import os
import json


class ChatStore:
    def __init__(self, base_dir="storage"):
        self.chats_dir = os.path.join(base_dir, "chats")
        os.makedirs(self.chats_dir, exist_ok=True)

    def _safe(self, chat_id: str) -> str:
        return chat_id.replace("/", "_").replace("\\", "_")

    def _path(self, chat_id: str) -> str:
        return os.path.join(self.chats_dir, f"{self._safe(chat_id)}.jsonl")

    def _legacy_path(self, chat_id: str) -> str:
        return os.path.join(self.chats_dir, f"{self._safe(chat_id)}.enc")

    def _migrate(self, chat_id: str):
        """One-time migration: convert old .enc (plain tokens) to .jsonl."""
        lp = self._legacy_path(chat_id)
        if not os.path.exists(lp):
            return
        np = self._path(chat_id)
        with open(lp, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        with open(np, "a", encoding="utf-8") as f:
            for token in lines:
                entry = {"token": token, "sender": None, "ts": None}
                f.write(json.dumps(entry, separators=(',', ':')) + "\n")
        os.remove(lp)

    def append_message(self, chat_id: str, entry):
        """
        entry can be:
          - a dict  {token, sender, ts, verified, plaintext}  (new format
            from web UI / network layer — 'verified' and 'plaintext' are
            both optional. 'plaintext': True means the 'token' field holds
            plaintext, not a ciphertext token — used for the sender's own
            local echo of a message they just sent (see router.py's
            Node.send() for why: the E2E scheme's ephemeral-static ECDH
            means not even the sender can decrypt their own ciphertext
            after the fact, so the plaintext is cached directly instead).
          - a str   raw token            (legacy / CLI usage)
        """
        self._migrate(chat_id)
        if isinstance(entry, str):
            entry = {"token": entry, "sender": None, "ts": None}
        # ensure required keys
        record = {
            "token":     entry.get("token", ""),
            "sender":    entry.get("sender"),
            "ts":        entry.get("ts"),
            "verified":  entry.get("verified"),
            "plaintext": entry.get("plaintext", False),
        }
        with open(self._path(chat_id), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(',', ':')) + "\n")

    def load_messages(self, chat_id: str) -> list:
        """Returns list of {token, sender, ts, verified, plaintext} dicts."""
        self._migrate(chat_id)
        path = self._path(chat_id)
        if not os.path.exists(path):
            return []
        entries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    rec.setdefault("plaintext", False)
                    entries.append(rec)
                except json.JSONDecodeError:
                    # bare token written directly (shouldn't happen after migration)
                    entries.append({"token": line, "sender": None, "ts": None,
                                     "verified": None, "plaintext": False})
        return entries

    def delete_chat(self, chat_id: str) -> bool:
        for p in (self._path(chat_id), self._legacy_path(chat_id)):
            if os.path.exists(p):
                os.remove(p)
                return True
        return False

    def has_chat(self, chat_id: str) -> bool:
        return os.path.exists(self._path(chat_id)) or os.path.exists(self._legacy_path(chat_id))

    def list_chats(self) -> list:
        chats = set()
        for f in os.listdir(self.chats_dir):
            if f.endswith(".jsonl"):
                chats.add(f[:-6])
            elif f.endswith(".enc"):
                chats.add(f[:-4])
        return sorted(chats)

    def message_count(self, chat_id: str) -> int:
        return len(self.load_messages(chat_id))
