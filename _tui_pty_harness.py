"""
Spawned inside a pty by the pty smoke test — not part of the app itself.
Pre-seeds a real identity + a peer + an existing message, then runs the
real TUIApp against real curses, so the smoke test exercises actual
rendering and key dispatch, not just the pure-logic layer.
"""
import curses
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

import main as app_core
from core.identity.key_manager import IdentityManager
from core.storage import ConfigStore, ChatStore, PeerStore
from tui import TUIApp

tmp = sys.argv[1]
port = int(sys.argv[2])

im = IdentityManager(storage_dir=os.path.join(tmp, "identity"))
im.generate_new_identity()
im.save_identity(passphrase="testpass123")

app_core.config = ConfigStore(base_dir=tmp)
app_core.chats = ChatStore(base_dir=tmp)
app_core.peers = PeerStore(base_dir=tmp)
app_core.identity = im
app_core._active_profile = "pty-smoke-test"

peer_id = "b" * 43
app_core.peers.upsert(user_id=peer_id, username="testbob",
                       ed25519_pub="x", x25519_pub="y", ip="127.0.0.1", port=9999)
app_core.chats.append_message(peer_id, {
    "token": "pre-seeded message text", "sender": "me",
    "ts": "2026-08-13T10:00:00+00:00", "verified": True, "plaintext": True,
})


def _run(stdscr):
    TUIApp(stdscr, passphrase_arg="testpass123", transport_port=port).run()


curses.wrapper(_run)
