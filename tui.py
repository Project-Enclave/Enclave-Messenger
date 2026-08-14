#!/usr/bin/env python3
"""
tui.py — Enclave Messenger terminal UI.

Vim-style modal curses interface. Imports main.py directly, the same
pattern web.py uses — no HTTP, no separate process, same coordinator API,
same profile model (one active profile per process; run separate
processes for separate simultaneous profiles — see core/profiles.py and
launch-two-instances.sh).

    python tui.py
    python tui.py --profile alice
    python tui.py --profile alice --passphrase secret   # skips the
                                                          # passphrase
                                                          # prompt — lands
                                                          # in shell
                                                          # history, so
                                                          # prefer the
                                                          # interactive
                                                          # prompt

Keys — NORMAL mode:
    j / k / Down / Up    move selection
    Enter                 open selected chat  (peers view: start/open a
                           chat with the selected peer)
    Tab                    switch focus between the list pane and the
                            message pane (Tab moves j/k to scroll messages)
    i                       enter INSERT mode to compose (opens a chat first
                             if none is open — actually requires one open)
    p                       switch to peers view
    c                       switch to chats view
    r                       refresh now
    :                       command mode
    q                       quit

INSERT mode:
    type your message, Enter to send, Esc to cancel (discards the draft)

Command mode (:):
    :q  :quit               quit
    :refresh                  refresh chats/peers/messages now
    :peers                     peers view
    :chats                      chats view
    :new <address>                start/open a chat — accepts a node id,
                                   phone number, or bluetooth MAC (same
                                   classification web.py's "+ new chat"
                                   modal uses, see main.py's
                                   classify_address())
"""

import argparse
import curses
import getpass
import sys
import time

import main as app_core

REFRESH_INTERVAL = 2.0  # seconds between background polls for new messages/peers


# ---------------------------------------------------------------------------
# Pure formatting helpers — no curses, no I/O, unit-testable directly.
# ---------------------------------------------------------------------------

def fmt_time(ts) -> str:
    """ISO timestamp -> 'HH:MM', tolerant of anything unparseable."""
    if not ts:
        return "--:--"
    try:
        from datetime import datetime
        s = ts.replace("Z", "+00:00") if isinstance(ts, str) else ts
        return datetime.fromisoformat(s).strftime("%H:%M")
    except Exception:
        return "--:--"


def truncate(s: str, width: int) -> str:
    if width <= 0:
        return ""
    s = s or ""
    if len(s) <= width:
        return s
    if width <= 1:
        return s[:width]
    return s[: width - 1] + "…"


def chat_list_label(chat: dict, peer_meta: dict | None) -> str:
    """What to show in the chat-list row for a {"id":.., "count":..} entry."""
    cid = chat.get("id", "")
    name = (peer_meta or {}).get("username") or cid
    count = chat.get("count", 0)
    return f"{name}  ({count})"


def peer_list_label(peer: dict) -> str:
    name = peer.get("username") or peer.get("user_id", "?")
    uid = peer.get("user_id", "")
    short = uid[:10] + "…" if len(uid) > 10 else uid
    return f"{name}  [{short}]"


def message_display_line(m: dict) -> tuple[str, str]:
    """
    Returns (prefix_label, text) for one message. prefix_label is empty
    for our own messages (right-aligned convention handled by the caller),
    otherwise the resolved author name.
    """
    me = m.get("sender") == "me"
    label = "" if me else (m.get("author") or m.get("sender") or "?")
    text = m.get("text", "")
    return label, text


# ---------------------------------------------------------------------------
# AppState — all UI state and pure transition logic, no curses calls here.
# This is the part covered directly by tests (see test_security_fixes.py).
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self):
        self.view = "chats"            # "chats" | "peers"
        self.mode = "normal"           # "normal" | "insert" | "command"
        self.focus = "list"            # "list" | "messages"
        self.chats: list = []
        self.peers: list = []
        self.selected_idx = 0
        self.current_chat_id = None
        self.messages: list = []
        self.message_scroll = 0
        self.compose_buffer = ""
        self.command_buffer = ""
        self.status = ""
        self.passphrase = ""
        self.running = True

    def visible_list(self) -> list:
        return self.peers if self.view == "peers" else self.chats

    def move_selection(self, delta: int):
        items = self.visible_list()
        if not items:
            self.selected_idx = 0
            return
        self.selected_idx = max(0, min(len(items) - 1, self.selected_idx + delta))

    def selected_item(self):
        items = self.visible_list()
        if not items or self.selected_idx >= len(items):
            return None
        return items[self.selected_idx]

    def target_chat_id_for_selection(self):
        item = self.selected_item()
        if item is None:
            return None
        return item.get("user_id") if self.view == "peers" else item.get("id")

    def set_view(self, view: str):
        assert view in ("chats", "peers")
        self.view = view
        self.selected_idx = 0

    def set_messages(self, chat_id: str, messages: list):
        self.current_chat_id = chat_id
        self.messages = messages
        self.message_scroll = max(0, len(messages) - 1)

    def scroll_messages(self, delta: int):
        if not self.messages:
            return
        self.message_scroll = max(0, min(len(self.messages) - 1, self.message_scroll + delta))

    def enter_insert(self) -> bool:
        if self.current_chat_id is None:
            self.status = "open a chat first — Enter on a chat, or :new <address>"
            return False
        self.mode = "insert"
        self.compose_buffer = ""
        return True

    def cancel_insert(self):
        self.mode = "normal"
        self.compose_buffer = ""

    def enter_command(self):
        self.mode = "command"
        self.command_buffer = ""

    def cancel_command(self):
        self.mode = "normal"
        self.command_buffer = ""

    def toggle_focus(self):
        self.focus = "messages" if self.focus == "list" else "list"


# ---------------------------------------------------------------------------
# Command-mode parsing — pure function, no side effects beyond returning
# what the caller should do. Kept separate from AppState so it's trivially
# testable: given a command string, what action comes out?
# ---------------------------------------------------------------------------

def parse_command(cmd: str):
    """
    Returns (action, arg). action is one of:
    "quit", "refresh", "view_chats", "view_peers", "new_chat", "unknown"
    """
    cmd = cmd.strip()
    if cmd in ("q", "quit"):
        return ("quit", None)
    if cmd == "refresh":
        return ("refresh", None)
    if cmd == "chats":
        return ("view_chats", None)
    if cmd == "peers":
        return ("view_peers", None)
    if cmd.startswith("new "):
        return ("new_chat", cmd[4:].strip())
    return ("unknown", cmd)


# ---------------------------------------------------------------------------
# Curses-facing driver. Everything that touches a real terminal or calls
# into app_core lives here; AppState above has none of that, by design.
# ---------------------------------------------------------------------------

class TUIApp:
    def __init__(self, stdscr, passphrase_arg=None, transport_port=None):
        self.scr = stdscr
        self.state = AppState()
        self._passphrase_arg = passphrase_arg
        self._transport_port = transport_port
        self._last_refresh = 0.0
        self._colors = False

    # ---- setup ----

    def _setup_colors(self):
        if not curses.has_colors():
            return
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        curses.init_pair(1, curses.COLOR_MAGENTA, bg)   # accent / header
        curses.init_pair(2, curses.COLOR_CYAN, bg)       # muted / timestamps
        curses.init_pair(3, curses.COLOR_RED, bg)        # errors
        curses.init_pair(4, curses.COLOR_GREEN, bg)      # verified badge
        curses.init_pair(5, curses.COLOR_YELLOW, bg)     # mode indicator
        self._colors = True

    def _c(self, n):
        return curses.color_pair(n) if self._colors else 0

    # ---- masked passphrase prompt (used before the main loop starts) ----

    def _prompt_passphrase(self, label: str):
        h, w = self.scr.getmaxyx()
        box = curses.newwin(3, min(60, w - 4), h // 2 - 1, max(0, (w - 60) // 2))
        box.keypad(True)
        buf = ""
        curses.curs_set(1)
        while True:
            box.erase()
            box.border()
            box.addstr(0, 2, f" {label} ")
            box.addstr(1, 2, "*" * len(buf))
            box.refresh()
            ch = box.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                curses.curs_set(0)
                return buf
            if ch == 27:  # Esc
                curses.curs_set(0)
                return None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                buf = buf[:-1]
            elif 32 <= ch <= 126:
                buf += chr(ch)

    def _message(self, text: str, pair=0, pause=1.2):
        h, w = self.scr.getmaxyx()
        win = curses.newwin(3, min(70, w - 4), h // 2 - 1, max(0, (w - 70) // 2))
        win.border()
        win.addstr(1, 2, truncate(text, w - 8), self._c(pair))
        win.refresh()
        time.sleep(pause)

    # ---- identity / node startup flow ----

    def _startup(self) -> bool:
        """Returns True if the node started successfully."""
        if not app_core.identity.has_identity():
            self._message("No identity for this profile — creating one.", pause=1.0)
            p1 = self._prompt_passphrase("choose a passphrase")
            if p1 is None:
                return False
            p2 = self._prompt_passphrase("confirm passphrase")
            if p2 is None:
                return False
            if p1 != p2:
                self._message("passphrases did not match", pair=3)
                return False
            app_core.identity.generate_new_identity()
            app_core.identity.save_identity(passphrase=p1)
            passphrase = p1
        else:
            passphrase = self._passphrase_arg
            if passphrase is None:
                passphrase = self._prompt_passphrase("passphrase")
                if passphrase is None:
                    return False

        self.state.passphrase = passphrase
        try:
            app_core.start_node(passphrase=passphrase, transport_port=self._transport_port)
        except RuntimeError as e:
            self._message(str(e), pair=3, pause=2.0)
            return False
        return True

    # ---- data refresh (polling — see REFRESH_INTERVAL) ----

    def _refresh(self, force=False):
        now = time.time()
        if not force and (now - self._last_refresh) < REFRESH_INTERVAL:
            return
        self._last_refresh = now
        self.state.chats = app_core.get_chats()
        self.state.peers = app_core.get_peers()
        if self.state.current_chat_id:
            msgs = app_core.get_messages_decrypted(
                self.state.current_chat_id, self.state.passphrase
            )
            # Preserve scroll position at "latest" only if we were already there
            was_at_end = self.state.message_scroll >= len(self.state.messages) - 1
            self.state.messages = msgs
            self.state.message_scroll = (
                len(msgs) - 1 if was_at_end else min(self.state.message_scroll, max(0, len(msgs) - 1))
            )

    def _open_chat(self, chat_id: str):
        msgs = app_core.get_messages_decrypted(chat_id, self.state.passphrase)
        self.state.set_messages(chat_id, msgs)
        self.state.status = ""

    # ---- rendering ----

    def _draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        list_w = max(20, min(32, w // 3))

        status = app_core.get_identity_status()
        header = f" project enclave — {status.get('username') or status.get('node_id', '')[:12]} "
        mode_tag = {"normal": "", "insert": "-- INSERT --", "command": ":"}[self.state.mode]
        self.scr.addstr(0, 0, truncate(header, w - 1), self._c(1) | curses.A_BOLD)
        if mode_tag:
            self.scr.addstr(0, max(0, w - len(mode_tag) - 1), mode_tag, self._c(5) | curses.A_BOLD)
        self.scr.hline(1, 0, curses.ACS_HLINE, w)

        self._draw_list(1, 0, h - 3, list_w)
        self.scr.vline(2, list_w, curses.ACS_VLINE, h - 4)
        self._draw_main(2, list_w + 1, h - 4, w - list_w - 1)

        self.scr.hline(h - 2, 0, curses.ACS_HLINE, w)
        self._draw_bottom(h - 1, w)
        self.scr.refresh()

    def _draw_list(self, top, left, height, width):
        items = self.state.visible_list()
        title = "peers" if self.state.view == "peers" else "chats"
        self.scr.addstr(top, left, f" {title} ", self._c(2) | curses.A_BOLD)
        if not items:
            self.scr.addstr(top + 2, left + 1, "(none yet)", self._c(2))
            return
        for i, item in enumerate(items):
            row = top + 1 + i
            if row >= top + height:
                break
            if self.state.view == "peers":
                label = peer_list_label(item)
            else:
                peer_meta = app_core.peers.get(item.get("id", ""))
                label = chat_list_label(item, peer_meta)
            attr = self._c(0)
            if i == self.state.selected_idx:
                attr = curses.A_REVERSE
            self.scr.addstr(row, left, truncate(" " + label, width - 1).ljust(width - 1), attr)

    def _draw_main(self, top, left, height, width):
        if self.state.current_chat_id is None:
            msg = "select a chat (Enter) — or :new <address>"
            self.scr.addstr(top + height // 2, left + max(0, (width - len(msg)) // 2),
                             truncate(msg, width), self._c(2))
            return

        self.scr.addstr(top, left, truncate(f" {self.state.current_chat_id} ", width),
                         self._c(2) | curses.A_BOLD)

        visible_h = height - 2
        msgs = self.state.messages
        start = max(0, len(msgs) - visible_h) if self.state.message_scroll >= len(msgs) - 1 \
            else max(0, self.state.message_scroll - visible_h + 1)
        row = top + 1
        for m in msgs[start:start + visible_h]:
            if row >= top + height:
                break
            label, text = message_display_line(m)
            ts = fmt_time(m.get("timestamp"))
            verified = " ✓" if m.get("verified") else ""
            if label:
                line = f"{ts} {label}: {text}{verified}"
            else:
                line = f"{ts} me: {text}{verified}"
            pair = self._c(4) if m.get("verified") else self._c(0)
            self.scr.addstr(row, left, truncate(line, width), pair)
            row += 1

    def _draw_bottom(self, row, w):
        if self.state.mode == "insert":
            self.scr.addstr(row, 0, truncate("> " + self.state.compose_buffer, w - 1))
        elif self.state.mode == "command":
            self.scr.addstr(row, 0, truncate(":" + self.state.command_buffer, w - 1))
        elif self.state.status:
            self.scr.addstr(row, 0, truncate(self.state.status, w - 1), self._c(3))
        else:
            hint = "j/k move  Enter open  i compose  p peers  c chats  : cmd  q quit"
            self.scr.addstr(row, 0, truncate(hint, w - 1), self._c(2))

    # ---- input handling ----

    def _handle_normal(self, ch):
        s = self.state
        if ch in (ord("j"), curses.KEY_DOWN):
            if s.focus == "messages":
                s.scroll_messages(1)
            else:
                s.move_selection(1)
        elif ch in (ord("k"), curses.KEY_UP):
            if s.focus == "messages":
                s.scroll_messages(-1)
            else:
                s.move_selection(-1)
        elif ch == ord("\t"):
            s.toggle_focus()
        elif ch in (curses.KEY_ENTER, 10, 13):
            if s.focus == "list":
                target = s.target_chat_id_for_selection()
                if target:
                    self._open_chat(target)
                    s.focus = "messages"
        elif ch == ord("i"):
            s.enter_insert()
        elif ch == ord("p"):
            s.set_view("peers")
        elif ch == ord("c"):
            s.set_view("chats")
        elif ch == ord("r"):
            self._refresh(force=True)
            s.status = "refreshed"
        elif ch == ord(":"):
            s.enter_command()
        elif ch == ord("q"):
            s.running = False

    def _handle_insert(self, ch):
        s = self.state
        if ch in (curses.KEY_ENTER, 10, 13):
            text = s.compose_buffer.strip()
            s.mode = "normal"
            s.compose_buffer = ""
            if text and s.current_chat_id:
                try:
                    ok = app_core.send_message(s.current_chat_id, text)
                    if not ok:
                        s.status = "send failed — peer may be offline"
                except Exception as e:
                    s.status = f"send error: {e}"
                self._open_chat(s.current_chat_id)  # refresh to show our own echo
        elif ch == 27:
            s.cancel_insert()
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            s.compose_buffer = s.compose_buffer[:-1]
        elif 32 <= ch <= 126:
            s.compose_buffer += chr(ch)

    def _handle_command(self, ch):
        s = self.state
        if ch in (curses.KEY_ENTER, 10, 13):
            cmd = s.command_buffer
            s.mode = "normal"
            s.command_buffer = ""
            self._run_command(cmd)
        elif ch == 27:
            s.cancel_command()
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            s.command_buffer = s.command_buffer[:-1]
        elif 32 <= ch <= 126:
            s.command_buffer += chr(ch)

    def _run_command(self, cmd: str):
        s = self.state
        action, arg = parse_command(cmd)
        if action == "quit":
            s.running = False
        elif action == "refresh":
            self._refresh(force=True)
            s.status = "refreshed"
        elif action == "view_chats":
            s.set_view("chats")
        elif action == "view_peers":
            s.set_view("peers")
        elif action == "new_chat":
            try:
                chat_id, _type = app_core.classify_address(arg)
                self._open_chat(chat_id)
                s.view = "chats"
                s.status = ""
            except ValueError as e:
                s.status = str(e)
        else:
            s.status = f"unknown command: {cmd}"

    # ---- main loop ----

    def run(self):
        curses.curs_set(0)
        self._setup_colors()
        self.scr.keypad(True)
        self.scr.timeout(200)  # ms — lets the loop poll for refresh without blocking forever

        if not self._startup():
            return

        self._refresh(force=True)
        try:
            while self.state.running:
                self._draw()
                ch = self.scr.getch()
                if ch == curses.KEY_RESIZE:
                    continue
                if ch != -1:
                    if self.state.mode == "normal":
                        self._handle_normal(ch)
                    elif self.state.mode == "insert":
                        self._handle_insert(ch)
                    elif self.state.mode == "command":
                        self._handle_command(ch)
                self._refresh()
        finally:
            app_core.stop_node()


def main():
    parser = argparse.ArgumentParser(prog="tui", description="Enclave Messenger terminal UI")
    parser.add_argument("--profile", default=None,
                         help="Profile name to run (defaults to active profile)")
    parser.add_argument("--passphrase", default=None,
                         help="Identity passphrase (prompted in-app if omitted — "
                              "prefer that over this flag, which lands in shell history)")
    parser.add_argument("--transport-port", type=int, default=None,
                         help="P2P transport port override")
    args = parser.parse_args()

    if args.profile:
        app_core.config, app_core.chats, app_core.peers, app_core.identity, \
            app_core.log, app_core._active_profile = app_core._init_stores(args.profile)

    def _run(stdscr):
        TUIApp(stdscr, passphrase_arg=args.passphrase,
               transport_port=args.transport_port).run()

    curses.wrapper(_run)


if __name__ == "__main__":
    sys.exit(main())
