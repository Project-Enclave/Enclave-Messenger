# core/storage.py
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path.home() / ".enclave-messenger"
CHATS_DIR = BASE_DIR / "chats"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(name: str) -> str:
    cleaned = [c if (c.isalnum() or c in "-_.") else "_" for c in name.strip()]
    out = "".join(cleaned).strip("._")
    return out or "chat"


def _ensure_dirs() -> None:
    CHATS_DIR.mkdir(parents=True, exist_ok=True)


class ChatStorage:
    def __init__(self, chat_id: str):
        _ensure_dirs()
        self.chat_id = _safe_filename(chat_id)
        self.db_path = CHATS_DIR / f"{self.chat_id}.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chat_meta (
                    chat_id TEXT PRIMARY KEY,
                    chat_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    enc_version INTEGER NOT NULL DEFAULT 1,
                    data TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id TEXT NOT NULL,
                    sender_id TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(chat_id) REFERENCES chat_meta(chat_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    chat_id TEXT PRIMARY KEY,
                    session_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(chat_id) REFERENCES chat_meta(chat_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_messages_chat_id_id ON messages(chat_id, id);
                """
            )
            now = _now()
            conn.execute(
                "INSERT OR IGNORE INTO chat_meta (chat_id, chat_name, created_at, updated_at, enc_version, data) VALUES (?, ?, ?, ?, 1, '{}')",
                (self.chat_id, self.chat_id, now, now),
            )

    def set_chat_name(self, chat_name: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE chat_meta SET chat_name = ?, updated_at = ? WHERE chat_id = ?", (chat_name, _now(), self.chat_id))

    def update_chat_data(self, data: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE chat_meta SET data = ?, updated_at = ? WHERE chat_id = ?", (json.dumps(data, ensure_ascii=False), _now(), self.chat_id))

    def get_chat_meta(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM chat_meta WHERE chat_id = ?", (self.chat_id,)).fetchone()
            if not row:
                return {}
            return {"chat_id": row["chat_id"], "chat_name": row["chat_name"], "created_at": row["created_at"], "updated_at": row["updated_at"], "enc_version": row["enc_version"], "data": json.loads(row["data"] or "{}")}

    def save_message(self, payload: dict[str, Any], sender_id: Optional[str] = None) -> int:
        encoded = json.dumps(payload, ensure_ascii=False)
        now = _now()
        with self._connect() as conn:
            cur = conn.execute("INSERT INTO messages (chat_id, sender_id, payload, created_at) VALUES (?, ?, ?, ?)", (self.chat_id, sender_id, encoded, now))
            conn.execute("UPDATE chat_meta SET updated_at = ? WHERE chat_id = ?", (now, self.chat_id))
            return int(cur.lastrowid)

    def get_messages(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, sender_id, payload, created_at FROM messages WHERE chat_id = ? ORDER BY id ASC LIMIT ? OFFSET ?", (self.chat_id, limit, offset)).fetchall()
            return [{"id": row["id"], "sender_id": row["sender_id"], "payload": json.loads(row["payload"]), "created_at": row["created_at"]} for row in rows]

    def save_session_state(self, session_state: dict[str, Any]) -> None:
        encoded = json.dumps(session_state, ensure_ascii=False)
        now = _now()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO sessions (chat_id, session_state, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET session_state = excluded.session_state, updated_at = excluded.updated_at
            """, (self.chat_id, encoded, now))

    def load_session_state(self) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT session_state FROM sessions WHERE chat_id = ?", (self.chat_id,)).fetchone()
            return json.loads(row[0]) if row else None
