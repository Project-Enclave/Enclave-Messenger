"""
chat_store.py — Per-chat message storage.
Each chat is a newline-delimited JSON file: storage/chats/<chat_id>.jsonl
Falls back to reading legacy .enc (plain token strings) transparently.
"""

import os
import json
import threading


class ChatStore:
    def __init__(self, base_dir="storage"):
        self.chats_dir = os.path.join(base_dir, "chats")
        os.makedirs(self.chats_dir, exist_ok=True)
        # Appends come from the network thread, rewrites (status updates,
        # clear_pending_contact) from request threads. Without a lock a
        # rewrite can silently drop a message appended mid-way through it.
        self._lock = threading.RLock()

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
            # True while this message's sender is an un-accepted contact
            # (see core/network/contacts.py) — the UI can use it to show
            # a "message request" style preview instead of a normal
            # conversation. Defaults False so every existing call site
            # (own local echo, bluetooth/legacy appends) is unaffected.
            "pending_contact": entry.get("pending_contact", False),
        }
        # Delivery state of OUR OWN outgoing messages. Only written when
        # given, so every older record and every inbound record is
        # byte-for-byte unchanged:
        #   status: "delivered" (peer reached directly) | "relayed"
        #           (handed to a relay, not yet confirmed) | "failed"
        #   via:    "direct" | "relay"
        # Id the message had where it came from (e.g. the SMS gateway's message id),
        # so a re-delivered webhook can be recognised and not stored twice.
        if entry.get("ext_id"):
            record["ext_id"] = entry["ext_id"]
        if entry.get("status"):
            record["status"] = entry["status"]
        if entry.get("via"):
            record["via"] = entry["via"]
        with self._lock:
            with open(self._path(chat_id), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(',', ':')) + "\n")

    def update_message(self, chat_id: str, ts: str, **fields) -> bool:
        """
        Update fields (e.g. status/via) of the message in this chat with
        timestamp `ts`. Only the delivery fields may be changed. Returns
        True if a record was updated.
        """
        allowed = {k: v for k, v in fields.items() if k in ("status", "via")}
        if not allowed or not ts:
            return False
        with self._lock:
            msgs = self.load_messages(chat_id)
            hit = False
            for m in msgs:
                if m.get("ts") == ts and m.get("sender") == "me":
                    m.update(allowed)
                    hit = True
                    break
            if not hit:
                return False
            tmp = self._path(chat_id) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for m in msgs:
                    f.write(json.dumps(m, separators=(',', ':')) + "\n")
            os.replace(tmp, self._path(chat_id))
            return True

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
                    rec.setdefault("pending_contact", False)
                    entries.append(rec)
                except json.JSONDecodeError:
                    # bare token written directly (shouldn't happen after migration)
                    entries.append({"token": line, "sender": None, "ts": None,
                                     "verified": None, "plaintext": False,
                                     "pending_contact": False})
        return entries

    def has_ext_id(self, chat_id: str, ext_id: str) -> bool:
        return bool(ext_id) and any(m.get("ext_id") == ext_id for m in self.load_messages(chat_id))

    def rewrite_messages(self, chat_id: str, fn) -> int:
        """
        Apply `fn(record) -> new_record | None` to every stored record of one
        chat (None = leave it alone) and write the result back atomically
        (temp file + rename, under the store lock, so a crash never leaves a
        half-written chat and a concurrent append is never lost). Returns the
        number of records that changed.
        """
        with self._lock:
            msgs = self.load_messages(chat_id)
            out, changed = [], 0
            for m in msgs:
                new = fn(dict(m))
                if new is not None and new != m:
                    out.append(new)
                    changed += 1
                else:
                    out.append(m)
            if not changed:
                return 0
            tmp = self._path(chat_id) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for m in out:
                    f.write(json.dumps(m, separators=(',', ':')) + "\n")
            os.replace(tmp, self._path(chat_id))
            return changed

    def clear_pending_contact(self, chat_id: str):
        """Flip pending_contact off for every stored message in this
        thread. Called once a contact request is accepted, so a "message
        request" thread becomes a normal conversation as a single step
        instead of the UI having to special-case old vs new messages
        forever. Silently does nothing if the chat doesn't exist yet.
        """
        with self._lock:
            msgs = self.load_messages(chat_id)
            if not msgs:
                return
            with open(self._path(chat_id), "w", encoding="utf-8") as f:
                for m in msgs:
                    m["pending_contact"] = False
                    f.write(json.dumps(m, separators=(',', ':')) + "\n")

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
