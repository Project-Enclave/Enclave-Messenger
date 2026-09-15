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
                                   phone number, bluetooth MAC, or a raw
                                   ip:port (same classification web.py's
                                   "+ new chat" modal uses, see main.py's
                                   classify_address())
    :profiles                      list profiles on this device
    :new-profile <name>              create a profile: prompts for a
                                      passphrase, creates its identity, and
                                      starts its web UI in the background
    :settings                          view/edit this profile's settings
    :help  :?                           key reference

Press ? in normal mode for the same help screen.
"""

import argparse
import curses
import getpass
import logging
import os
import subprocess
import sys
import time

import main as app_core
from core import profiles as _profiles

REFRESH_INTERVAL = 2.0  # seconds between background polls for new messages/peers


def _silence_console_logging():
    """
    core/storage/log_store.py attaches a console StreamHandler (WARNING+)
    to the root logger. That's correct for main.py/web.py — stderr output
    there is harmless. It is NOT harmless here: curses owns the whole
    terminal, so anything else writing to stdout/stderr corrupts the
    display outright.

    This was a real reported bug, not a hypothetical: a single failed
    send printed "[transport] send failed to ... Connection refused"
    straight into the middle of the chat input line. Mute the console
    handler only — the file handler stays, so logs are still on disk for
    debugging.
    """
    for h in logging.getLogger().handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.setLevel(logging.CRITICAL + 1)


# Editable settings, rendered by the :settings screen. "kind" drives how
# Enter behaves: text prompts for a value, bool toggles immediately.
SETTINGS_FIELDS = [
    {"key": "username",      "label": "display name",             "kind": "text"},
    {"key": "network_bind",  "label": "LAN mode (lan / host)",    "kind": "text"},
    {"key": "dht_enabled",   "label": "DHT (internet discovery)", "kind": "bool"},
    {"key": "dht_bootstrap", "label": "DHT bootstrap nodes",      "kind": "list"},
    {"key": "dht_public_ip", "label": "DHT public IP override",   "kind": "text"},
]

HELP_TEXT = [
    "NORMAL mode",
    "  j / k / Down / Up    move selection",
    "  Enter                 open chat  (peers view: start a chat)",
    "  Tab                   switch focus: list <-> messages",
    "  i                     compose a message (needs an open chat)",
    "  p / c                 peers view / chats view",
    "  r                     refresh now",
    "  ?                     this help",
    "  :                     command mode",
    "  q                     quit",
    "",
    "INSERT mode",
    "  type, Enter sends, Esc cancels (discards the draft)",
    "",
    "COMMAND mode  (:)",
    "  :q  :quit             quit",
    "  :refresh              refresh chats/peers/messages now",
    "  :peers  :chats        switch views",
    "  :new <address>        start/open a chat. accepts a node id, a",
    "                        phone number, a bluetooth MAC, or ip:port",
    "  :profiles             list every profile on this device",
    "  :new-profile <name>   create another profile — prompts for a",
    "                        passphrase, creates its identity, and starts",
    "                        its web UI in the background",
    "  :settings             view and edit this profile's settings",
    "  :help  :?             this help",
    "",
    "press any key to close",
]


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

        # Full-screen overlays: None | "help" | "profiles" | "settings".
        # These take over both drawing and key handling while open, so the
        # underlying chat/peer navigation state is left completely alone
        # and is exactly as it was when the overlay closes.
        self.overlay = None
        self.overlay_idx = 0
        self.profiles: list = []
        self.settings_values: dict = {}

    def open_overlay(self, name: str):
        self.overlay = name
        self.overlay_idx = 0

    def close_overlay(self):
        self.overlay = None
        self.overlay_idx = 0

    def move_overlay_selection(self, delta: int, length: int):
        if length <= 0:
            self.overlay_idx = 0
            return
        self.overlay_idx = max(0, min(length - 1, self.overlay_idx + delta))

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
    "quit", "refresh", "view_chats", "view_peers", "new_chat",
    "profiles", "new_profile", "settings", "help", "unknown"

    NOTE on ordering: "new-profile" must be checked before "new ", or
    ":new-profile foo" would parse as new_chat("-profile foo"). Tested
    for explicitly in test_tui.py rather than left to reviewer vigilance.
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
    if cmd == "profiles":
        return ("profiles", None)
    if cmd == "settings":
        return ("settings", None)
    if cmd in ("help", "?"):
        return ("help", None)
    if cmd.startswith("new-profile"):
        return ("new_profile", cmd[len("new-profile"):].strip())
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

    def _prompt_text(self, label: str, mask: bool = False, initial: str = ""):
        """
        Modal single-line input. Returns the string, or None if cancelled
        with Esc. mask=True renders asterisks (passphrases); everything
        else shows what you typed, which matters for settings where you
        need to see the value you're editing.
        """
        h, w = self.scr.getmaxyx()
        box_w = min(70, max(20, w - 4))
        box = curses.newwin(3, box_w, h // 2 - 1, max(0, (w - box_w) // 2))
        box.keypad(True)
        buf = initial
        curses.curs_set(1)
        try:
            while True:
                box.erase()
                box.border()
                box.addstr(0, 2, f" {truncate(label, box_w - 6)} ")
                shown = "*" * len(buf) if mask else buf
                # Keep the tail visible when the value is longer than the box.
                shown = shown[-(box_w - 4):]
                box.addstr(1, 2, shown)
                box.refresh()
                ch = box.getch()
                if ch in (curses.KEY_ENTER, 10, 13):
                    return buf
                if ch == 27:  # Esc
                    return None
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    buf = buf[:-1]
                elif 32 <= ch <= 126:
                    buf += chr(ch)
        finally:
            curses.curs_set(0)

    def _prompt_passphrase(self, label: str):
        return self._prompt_text(label, mask=True)

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
            self._message("No identity for this profile — creating one.", pause=5.0)
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

    # ---- profiles / settings data ----

    def _load_profiles(self):
        try:
            self.state.profiles = _profiles.list_profiles()
        except Exception as e:
            self.state.profiles = []
            self.state.status = f"could not read profiles: {e}"

    def _load_settings(self):
        cfg = app_core.config
        self.state.settings_values = {
            "username":      cfg.username or "",
            "network_bind":  cfg.get_setting("network_bind", "lan"),
            "dht_enabled":   bool(cfg.get_setting("dht_enabled", False)),
            "dht_bootstrap": cfg.get_setting("dht_bootstrap", []) or [],
            "dht_public_ip": cfg.get_setting("dht_public_ip", "") or "",
        }

    def _edit_selected_setting(self):
        field = SETTINGS_FIELDS[self.state.overlay_idx]
        key, kind = field["key"], field["kind"]
        cfg = app_core.config

        if kind == "bool":
            new_value = not self.state.settings_values.get(key)
            cfg.set_setting(key, new_value)
            self.state.status = f"{field['label']}: {'on' if new_value else 'off'} (applies on next node start)"
        else:
            current = self.state.settings_values.get(key)
            initial = ", ".join(current) if kind == "list" and current else (str(current) if current else "")
            entered = self._prompt_text(field["label"], initial=initial)
            if entered is None:
                return  # cancelled — leave the stored value untouched
            entered = entered.strip()
            if kind == "list":
                items = [x.strip() for x in entered.replace("\n", ",").split(",") if x.strip()]
                cfg.set_setting(key, items)
            elif key == "username":
                cfg.username = entered
            else:
                cfg.set_setting(key, entered or None)
            self.state.status = f"{field['label']} updated (applies on next node start)"

        self._load_settings()

    def _create_profile_interactive(self, name: str):
        """
        :new-profile — the TUI counterpart to the web UI's profile
        creation. Same shared backend call (create_profile_with_identity),
        so both surfaces create profiles identically, and same follow-up:
        actually start the new profile's web UI so it's usable
        immediately rather than just being a registry entry.
        """
        name = (name or "").strip()
        if not name:
            entered = self._prompt_text("new profile name")
            if entered is None:
                return
            name = entered.strip()
        if not name:
            self.state.status = "profile name required"
            return

        p1 = self._prompt_passphrase(f"passphrase for '{name}'")
        if p1 is None:
            return
        if not p1:
            self.state.status = "passphrase required — a profile with no identity can't be unlocked"
            return
        p2 = self._prompt_passphrase("confirm passphrase")
        if p2 is None:
            return
        if p1 != p2:
            self.state.status = "passphrases did not match — profile not created"
            return

        try:
            profile = app_core.create_profile_with_identity(name=name, passphrase=p1)
        except ValueError as e:
            self.state.status = str(e)
            return
        except Exception as e:
            self.state.status = f"profile registered but identity creation failed: {e}"
            return

        pid, err = self._spawn_profile_web(name, profile.get("web_port"))
        if pid:
            self.state.status = (f"created '{name}' — web UI on :{profile.get('web_port')} "
                                  f"(pid {pid})")
        else:
            self.state.status = (f"created '{name}', but couldn't start it: {err} — "
                                  f"run: python3 web.py --profile {name} "
                                  f"--port {profile.get('web_port')}")
        self._load_profiles()

    def _spawn_profile_web(self, name: str, web_port):
        """
        Starts a profile's web UI as a detached background process.
        Returns (pid, None) or (None, error_string).

        The PID is also printed to the ORIGINAL terminal's stdout (the one
        that launched this TUI) so there's a record of it after the TUI
        exits and the curses screen is gone — you need that pid to stop
        the thing later, and a status line that disappears on the next
        keypress is no use for that.
        """
        try:
            repo_dir = os.path.dirname(os.path.abspath(__file__))
            proc = subprocess.Popen(
                [sys.executable, os.path.join(repo_dir, "web.py"),
                 "--profile", name, "--port", str(web_port)],
                cwd=repo_dir,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                # Goes to the real terminal, not the curses screen. Harmless
                # here because curses redraws the full screen every loop
                # iteration anyway, and this lands in the scrollback that
                # survives after the TUI exits.
                print(f"[enclave] started profile '{name}' on port {web_port} — pid {proc.pid}",
                      file=sys.__stdout__, flush=True)
            except Exception:
                pass
            return proc.pid, None
        except OSError as e:
            return None, str(e)

    # ---- rendering ----

    def _draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()

        status = app_core.get_identity_status()
        header = f" project enclave — {status.get('username') or status.get('node_id', '')[:12]} "
        mode_tag = {"normal": "", "insert": "-- INSERT --", "command": ":"}[self.state.mode]
        self.scr.addstr(0, 0, truncate(header, w - 1), self._c(1) | curses.A_BOLD)
        if mode_tag:
            self.scr.addstr(0, max(0, w - len(mode_tag) - 1), mode_tag, self._c(5) | curses.A_BOLD)
        self.scr.hline(1, 0, curses.ACS_HLINE, w)

        if self.state.overlay:
            self._draw_overlay(2, h - 4, w)
        else:
            list_w = max(20, min(32, w // 3))
            self._draw_list(1, 0, h - 3, list_w)
            self.scr.vline(2, list_w, curses.ACS_VLINE, h - 4)
            self._draw_main(2, list_w + 1, h - 4, w - list_w - 1)

        self.scr.hline(h - 2, 0, curses.ACS_HLINE, w)
        self._draw_bottom(h - 1, w)
        self.scr.refresh()

    # ---- overlays: help / profiles / settings ----

    def _draw_overlay(self, top, height, width):
        name = self.state.overlay
        if name == "help":
            self._draw_help(top, height, width)
        elif name == "profiles":
            self._draw_profiles(top, height, width)
        elif name == "settings":
            self._draw_settings(top, height, width)

    def _draw_help(self, top, height, width):
        self.scr.addstr(top, 1, " help ", self._c(2) | curses.A_BOLD)
        for i, line in enumerate(HELP_TEXT):
            row = top + 2 + i
            if row >= top + height:
                break
            # Section headers (no leading spaces, non-empty) get the accent
            # colour so the three modes are scannable at a glance.
            attr = self._c(1) | curses.A_BOLD if line and not line.startswith(" ") else self._c(0)
            self.scr.addstr(row, 2, truncate(line, width - 3), attr)

    def _draw_profiles(self, top, height, width):
        self.scr.addstr(top, 1, " profiles ", self._c(2) | curses.A_BOLD)
        hint = "Enter: copy launch command   n: new profile   Esc: close"
        self.scr.addstr(top + 1, 2, truncate(hint, width - 3), self._c(2))

        if not self.state.profiles:
            self.scr.addstr(top + 3, 2, "(no profiles found)", self._c(2))
            return

        active = app_core.get_identity_status().get("profile")
        for i, p in enumerate(self.state.profiles):
            row = top + 3 + i
            if row >= top + height:
                break
            name = p.get("name", "?")
            mark = " (this one)" if name == active else ""
            label = (f" {name}{mark}   web :{p.get('web_port', '?')}"
                      f"   transport :{p.get('transport_port', '?')}")
            attr = curses.A_REVERSE if i == self.state.overlay_idx else self._c(0)
            self.scr.addstr(row, 1, truncate(label, width - 2).ljust(width - 2), attr)

    def _draw_settings(self, top, height, width):
        self.scr.addstr(top, 1, " settings ", self._c(2) | curses.A_BOLD)
        hint = "Enter: edit / toggle   Esc: close   (applies on next node start)"
        self.scr.addstr(top + 1, 2, truncate(hint, width - 3), self._c(2))

        for i, field in enumerate(SETTINGS_FIELDS):
            row = top + 3 + i
            if row >= top + height:
                break
            raw = self.state.settings_values.get(field["key"])
            if field["kind"] == "bool":
                shown = "on" if raw else "off"
            elif field["kind"] == "list":
                shown = ", ".join(raw) if raw else "(none)"
            else:
                shown = str(raw) if raw else "(not set)"
            label = f" {field['label']:<32} {shown}"
            attr = curses.A_REVERSE if i == self.state.overlay_idx else self._c(0)
            self.scr.addstr(row, 1, truncate(label, width - 2).ljust(width - 2), attr)

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
            hint = "j/k move  Enter open  i compose  p peers  c chats  ? help  : cmd  q quit"
            self.scr.addstr(row, 0, truncate(hint, w - 1), self._c(2))

    # ---- input handling ----

    def _handle_overlay(self, ch):
        """
        Overlays own all key input while open, so normal-mode navigation
        can't fire underneath them. Esc (and q) always closes.
        """
        s = self.state
        if s.overlay == "help":
            s.close_overlay()  # help closes on any key, as its footer says
            return

        length = (len(s.profiles) if s.overlay == "profiles" else len(SETTINGS_FIELDS))

        if ch in (27, ord("q")):
            s.close_overlay()
        elif ch in (ord("j"), curses.KEY_DOWN):
            s.move_overlay_selection(1, length)
        elif ch in (ord("k"), curses.KEY_UP):
            s.move_overlay_selection(-1, length)
        elif ch in (curses.KEY_ENTER, 10, 13):
            if s.overlay == "settings":
                self._edit_selected_setting()
            elif s.overlay == "profiles" and s.profiles:
                p = s.profiles[s.overlay_idx]
                s.status = (f"python3 web.py --profile {p.get('name')} "
                             f"--port {p.get('web_port')}")
        elif ch == ord("n") and s.overlay == "profiles":
            self._create_profile_interactive("")

    def _handle_normal(self, ch):
        s = self.state
        if ch == ord("?"):
            s.open_overlay("help")
        elif ch in (ord("j"), curses.KEY_DOWN):
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
                chat_id, addr_type = app_core.classify_address(arg)
                if addr_type == "ip":
                    # ip:port needs a live round trip to learn who's there
                    # before a chat means anything — see _connect_by_address.
                    self._connect_by_address(chat_id)
                else:
                    self._open_chat(chat_id)
                    s.view = "chats"
                    s.status = ""
            except ValueError as e:
                s.status = str(e)
        elif action == "profiles":
            self._load_profiles()
            s.open_overlay("profiles")
        elif action == "new_profile":
            self._create_profile_interactive(arg)
        elif action == "settings":
            self._load_settings()
            s.open_overlay("settings")
        elif action == "help":
            s.open_overlay("help")
        else:
            s.status = f"unknown command: {cmd}"

    def _connect_by_address(self, address: str):
        """:new <ip:port> — resolve a manual address into a real peer."""
        s = self.state
        node = app_core.get_node()
        if node is None:
            s.status = "node isn't running — can't connect to an address yet"
            return
        try:
            peer = node.connect_to_address(address)
        except Exception as e:
            s.status = f"could not connect to {address}: {e}"
            return
        if not peer:
            s.status = f"no enclave node answered at {address}"
            return
        self._refresh(force=True)
        self._open_chat(peer["user_id"])
        s.view = "chats"
        s.status = f"connected to {peer.get('username') or peer['user_id'][:12]}"

    # ---- main loop ----

    def run(self):
        _silence_console_logging()
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
                    # Overlays intercept everything so the chat view
                    # underneath can't react to keys meant for them.
                    if self.state.overlay:
                        self._handle_overlay(ch)
                    elif self.state.mode == "normal":
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
