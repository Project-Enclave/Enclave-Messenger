"""
test_tui.py — tests for tui.py.

Two layers:
1. Pure logic (AppState, parse_command, formatting helpers) — no curses,
   no terminal, runs instantly.
2. A real integration smoke test that drives the actual curses app under
   a pseudo-terminal (pty) via _tui_pty_harness.py, so rendering and key
   dispatch are exercised for real, not just the decisions underneath them.

Run: python3 test_tui.py
"""
import fcntl
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

sys.path.insert(0, os.path.dirname(__file__))

from tui import (
    AppState, parse_command, fmt_time, truncate,
    chat_list_label, peer_list_label, message_display_line,
)

PASS, FAIL = [], []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def test_pure_logic():
    s = AppState()
    s.chats = [{"id": "a", "count": 1}, {"id": "b", "count": 2}, {"id": "c", "count": 0}]
    s.move_selection(1)
    check("move_selection down", s.selected_idx == 1)
    s.move_selection(1)
    check("move_selection down again", s.selected_idx == 2)
    s.move_selection(1)
    check("move_selection clamps at bottom", s.selected_idx == 2)
    s.move_selection(-5)
    check("move_selection clamps at top", s.selected_idx == 0)
    check("selected_item returns the right chat", s.selected_item()["id"] == "a")

    s.selected_idx = 1
    check("target_chat_id_for_selection (chats view)", s.target_chat_id_for_selection() == "b")

    s.set_view("peers")
    check("set_view resets selection", s.selected_idx == 0)
    s.peers = [{"user_id": "peerA", "username": "alice"}]
    check("target_chat_id_for_selection (peers view)", s.target_chat_id_for_selection() == "peerA")

    s2 = AppState()
    s2.move_selection(1)
    check("move_selection on empty list doesn't crash", s2.selected_idx == 0)
    check("selected_item on empty list returns None", s2.selected_item() is None)

    s3 = AppState()
    check("enter_insert refused with no chat open", s3.enter_insert() is False and s3.mode == "normal")
    s3.current_chat_id = "x"
    check("enter_insert allowed once a chat is open", s3.enter_insert() is True and s3.mode == "insert")
    s3.compose_buffer = "hello"
    s3.cancel_insert()
    check("cancel_insert clears buffer and mode", s3.mode == "normal" and s3.compose_buffer == "")

    s4 = AppState()
    s4.set_messages("x", [{"text": f"m{i}"} for i in range(5)])
    check("set_messages snaps scroll to latest", s4.message_scroll == 4)
    s4.scroll_messages(-100)
    check("scroll_messages clamps at 0", s4.message_scroll == 0)
    s4.scroll_messages(100)
    check("scroll_messages clamps at max", s4.message_scroll == 4)

    check(":q parses to quit", parse_command("q") == ("quit", None))
    check(":quit parses to quit", parse_command("quit") == ("quit", None))
    check(":peers parses correctly", parse_command("peers") == ("view_peers", None))
    check(":chats parses correctly", parse_command("chats") == ("view_chats", None))
    check(":refresh parses correctly", parse_command("refresh") == ("refresh", None))
    check(":new <addr> extracts the address",
          parse_command("new AA:BB:CC:DD:EE:FF") == ("new_chat", "AA:BB:CC:DD:EE:FF"))
    check("unknown command falls through cleanly", parse_command("bogus") == ("unknown", "bogus"))

    check("fmt_time handles a real ISO timestamp",
          fmt_time("2026-08-13T11:25:57.893311+00:00") == "11:25")
    check("fmt_time tolerates garbage", fmt_time("not a date") == "--:--")
    check("fmt_time tolerates None", fmt_time(None) == "--:--")
    check("truncate leaves short strings alone", truncate("hi", 10) == "hi")
    check("truncate shortens with ellipsis", truncate("hello world", 8) == "hello w…")
    check("truncate handles width<=1", truncate("hello", 1) == "h")

    check("chat_list_label prefers peer username",
          chat_list_label({"id": "enc_xyz", "count": 3}, {"username": "bob"}) == "bob  (3)")
    check("chat_list_label falls back to id with no peer meta",
          chat_list_label({"id": "enc_xyz", "count": 3}, None) == "enc_xyz  (3)")

    check("peer_list_label shows name + truncated id",
          peer_list_label({"user_id": "a" * 20, "username": "carol"}).startswith("carol  ["))

    lbl, txt = message_display_line({"sender": "me", "text": "hi"})
    check("message_display_line: own message has empty label", lbl == "" and txt == "hi")
    lbl2, txt2 = message_display_line({"sender": "abc123", "author": "bob", "text": "yo"})
    check("message_display_line: resolves author for others", lbl2 == "bob" and txt2 == "yo")


def _strip_ansi(b: bytes) -> bytes:
    return re.sub(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b\(B|\x1b[=>]', b'', b)


def test_pty_integration():
    """
    Drives the real curses app under a pseudo-terminal. Note: curses only
    retransmits CHANGED cells on each redraw (screen diffing), so a raw
    substring check against a single diff chunk can miss text that's
    unchanged from the previous frame — this bit us once already (see the
    'p switches to peers view' case below, which checks for the part that
    actually gets retransmitted rather than the full word).
    """
    tmp = tempfile.mkdtemp()
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"

    proc = subprocess.Popen(
        ["python3", "_tui_pty_harness.py", tmp, "53301"],
        stdin=slave, stdout=slave, stderr=slave, env=env,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        preexec_fn=os.setsid,
    )
    os.close(slave)

    def read_screen(timeout=1.5):
        end = time.time() + timeout
        buf = b""
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.2)
            if master in r:
                try:
                    chunk = os.read(master, 65536)
                    if not chunk:
                        break
                    buf += chunk
                except OSError:
                    break
        return buf

    def send(s):
        os.write(master, s.encode())

    try:
        time.sleep(1.5)  # let curses.wrapper + identity load settle
        screen1 = _strip_ansi(read_screen())
        check("startup: header shows 'project enclave'", b"project enclave" in screen1)
        check("startup: chat list shows the pre-seeded peer's chat", b"testbob" in screen1)

        send("\r")
        time.sleep(0.6)
        screen2 = _strip_ansi(read_screen())
        check("open chat: pre-seeded message text visible", b"pre-seeded message text" in screen2)
        check("open chat: verified checkmark shown", "✓".encode() in screen2)

        send("i")
        time.sleep(0.3)
        send("hello from pty test")
        time.sleep(0.3)
        screen3 = _strip_ansi(read_screen())
        check("insert mode: -- INSERT -- indicator shown", b"INSERT" in screen3)
        check("insert mode: typed text appears in the compose line",
              b"hello from pty test" in screen3)

        send(chr(27))  # Esc — cancel without sending
        time.sleep(0.3)
        screen4 = _strip_ansi(read_screen())
        check("Esc cancels insert: compose text cleared", b"hello from pty test" not in screen4)
        check("Esc cancels insert: back to normal mode", b"INSERT" not in screen4)

        send("p")
        time.sleep(0.6)
        screen5 = _strip_ansi(read_screen())
        # "testbob" doesn't need to be re-checked here — it occupies the
        # same screen cells in both chat and peer rows for this fixture,
        # so it's already on screen and correctly NOT retransmitted. What
        # DOES change and get sent: "chats" -> "peer..." (title) and the
        # bracketed id suffix.
        check("'p' switches to peers view (title cell updates to 'peer')", b"peer" in screen5)

        send("q")
        time.sleep(0.8)
        try:
            proc.wait(timeout=3)
            check("process exits cleanly after 'q'", proc.returncode == 0)
        except subprocess.TimeoutExpired:
            check("process exits cleanly after 'q'", False)
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    test_pure_logic()
    test_new_command_parsing()
    test_overlay_state()
    test_ip_port_connect()
    test_pty_integration()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1




# ---------------------------------------------------------------------------
# Additions: command parsing for the new screens, and the ip:port handshake.
# ---------------------------------------------------------------------------

def test_new_command_parsing():
    from tui import parse_command
    check(":profiles parses", parse_command("profiles") == ("profiles", None))
    check(":settings parses", parse_command("settings") == ("settings", None))
    check(":help parses", parse_command("help") == ("help", None))
    check(":? parses as help", parse_command("?") == ("help", None))
    check(":new-profile with a name parses",
          parse_command("new-profile work") == ("new_profile", "work"))
    check(":new-profile with no name parses (prompts interactively)",
          parse_command("new-profile") == ("new_profile", ""))
    # Ordering trap: ":new-profile x" must NOT be read as new_chat("-profile x").
    check(":new-profile is not mis-parsed as :new",
          parse_command("new-profile x")[0] == "new_profile")
    check(":new still parses as new_chat",
          parse_command("new abc123") == ("new_chat", "abc123"))


def test_overlay_state():
    from tui import AppState, SETTINGS_FIELDS
    s = AppState()
    check("no overlay by default", s.overlay is None)
    s.open_overlay("settings")
    check("open_overlay sets the overlay and resets index",
          s.overlay == "settings" and s.overlay_idx == 0)
    s.move_overlay_selection(1, len(SETTINGS_FIELDS))
    check("overlay selection moves", s.overlay_idx == 1)
    s.move_overlay_selection(-99, len(SETTINGS_FIELDS))
    check("overlay selection clamps at 0", s.overlay_idx == 0)
    s.move_overlay_selection(99, len(SETTINGS_FIELDS))
    check("overlay selection clamps at the end", s.overlay_idx == len(SETTINGS_FIELDS) - 1)
    s.move_overlay_selection(1, 0)
    check("empty overlay list doesn't crash", s.overlay_idx == 0)
    s.close_overlay()
    check("close_overlay clears it", s.overlay is None)

    # Opening an overlay must not disturb the chat view underneath.
    s2 = AppState()
    s2.chats = [{"id": "a"}, {"id": "b"}]
    s2.selected_idx = 1
    s2.current_chat_id = "b"
    s2.open_overlay("help")
    s2.close_overlay()
    check("underlying chat state survives an overlay round trip",
          s2.selected_idx == 1 and s2.current_chat_id == "b")


def test_ip_port_connect():
    """
    Manual ip:port peering. Deliberately run with network_bind=host on
    both nodes so LAN discovery is fully disabled — if this passes, the
    connection genuinely came from the /identity handshake and not from
    discovery quietly finding them anyway.
    """
    import tempfile as _tf
    from core.identity.key_manager import IdentityManager
    from core.storage import ConfigStore, ChatStore, PeerStore
    from core.network.router import Node
    from main import classify_address

    check("classify_address now recognises ip:port",
          classify_address("192.168.0.5:4000") == ("192.168.0.5:4000", "ip"))

    tmp = _tf.mkdtemp()

    def mk(label, tport):
        d = os.path.join(tmp, label)
        os.makedirs(d)
        im = IdentityManager(storage_dir=os.path.join(d, "identity"))
        im.generate_new_identity()
        cfg = ConfigStore(base_dir=d)
        cfg.set_setting("network_port", tport)
        cfg.set_setting("network_bind", "host")
        return Node(im, cfg, PeerStore(base_dir=d), ChatStore(base_dir=d))

    alice = mk("ipc_alice", 62101)
    bob = mk("ipc_bob", 62102)
    alice.start()
    bob.start()
    time.sleep(0.5)

    try:
        check("alice starts knowing nobody (discovery is off)", len(alice._peers.all()) == 0)

        peer = alice.connect_to_address("127.0.0.1:62102")
        check("connect_to_address resolves a peer", peer is not None)
        check("it resolved the right identity",
              peer and peer["user_id"] == bob._identity["user_id"])
        check("it stored the real x25519 key (so encryption can work)",
              peer and peer["x25519_pub"] == bob._identity["x25519_pub"])
        check("an http:// prefix is tolerated",
              alice.connect_to_address("http://127.0.0.1:62102") is not None)

        bob._peers.upsert(user_id=alice._identity["user_id"], username="alice",
                          ed25519_pub=alice._identity["ed25519_pub"],
                          x25519_pub=alice._identity["x25519_pub"],
                          ip="127.0.0.1", port=62101)
        sent = alice.send(bob._identity["user_id"], "hello via manual ip:port")
        time.sleep(0.4)
        check("a message actually sends to a manually-added peer", sent)
        check("and the peer receives it",
              len(bob._chats.load_messages(alice._identity["user_id"])) == 1)

        try:
            alice.connect_to_address("not-an-address")
            check("a malformed address raises", False)
        except ValueError:
            check("a malformed address raises", True)

        check("an address with nothing listening returns None",
              alice.connect_to_address("127.0.0.1:62999") is None)

        try:
            alice.connect_to_address("127.0.0.1:62101")
            check("connecting to yourself is rejected", False)
        except ValueError as e:
            check("connecting to yourself is rejected", "itself" in str(e))

        # Same key-pinning rule discovery uses: typed by hand is not more
        # trustworthy than broadcast.
        alice._peers.upsert(user_id=bob._identity["user_id"], username="bob",
                            ed25519_pub="DIFFERENT", x25519_pub="DIFFERENT",
                            ip="9.9.9.9", port=1)
        try:
            alice.connect_to_address("127.0.0.1:62102")
            check("a key change at a manual address is refused", False)
        except ValueError as e:
            check("a key change at a manual address is refused", "different keys" in str(e))
    finally:
        alice.stop()
        bob.stop()


if __name__ == "__main__":
    sys.exit(main())
