"""
main.py — Enclave Messenger coordinator.

This is the heart of the app. It wires up all core modules and exposes
a clean API that web.py, tui.py, gui.py etc. import directly.

Running directly:
    python main.py run              # start node (discovery + transport)
    python main.py run --passphrase secret

CLI utilities :
    python main.py init
    python main.py encrypt ...
    python main.py decrypt ...
    python main.py sms send ...
    python main.py bt scan
    python main.py bt send --to AA:BB:CC:DD:EE:FF --message "Hello"

Note: This is the same as the ~/core.py from the first couple of versions.
"""

import argparse
import json
import sys
import signal
import threading

from core.identity import IdentityManager
from core.crypto import CryptoManager
from core.crypto.e2e import E2EManager
from core.storage import ConfigStore, ChatStore, PeerStore, LogStore
from core.plugins.builtin.smsgateway import SMSGateway, PluginManager
from core.plugins.builtin.bluetooth.main import (
    BluetoothPlugin,
    BluetoothUnavailableError,
    is_bt_chat_id,
    chat_id_from_mac,
)
from core.network import Node

# ---------------------------------------------------------------------------
# Singletons — initialised once, imported by web.py / tui.py / gui.py
# ---------------------------------------------------------------------------

config   = ConfigStore()
chats    = ChatStore()
peers    = PeerStore()
identity = IdentityManager()
log      = LogStore(name="enclave")

# Plugin manager — discovered on import, enabled after node starts.
plugin_manager = PluginManager(
    config=config,
    peers=peers,
    chats=chats,
    identity=identity,
    log=log,
)
plugin_manager.discover()

# The Node is None until start_node() is called.
_node: Node | None = None
_node_lock = threading.Lock()

# Bluetooth plugin instance — created once, listener started in start_node().
_bt: BluetoothPlugin | None = None
_bt_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Bluetooth helpers
# ---------------------------------------------------------------------------

def _bt_on_message(chat_id: str, plaintext: str) -> None:
    """
    Callback fired by the Bluetooth listener thread when a message arrives.
    Stores the message in ChatStore so the UI picks it up on the next poll
    or WebSocket push.
    """
    import datetime
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    chats.append_message(chat_id, {"token": plaintext, "sender": "peer", "ts": ts})
    log.info(f"[bluetooth] received message from {chat_id}")


def get_bluetooth() -> BluetoothPlugin:
    """
    Return the shared BluetoothPlugin instance, creating it on first call.
    """
    global _bt
    with _bt_lock:
        if _bt is None:
            _bt = BluetoothPlugin(on_message=_bt_on_message)
        return _bt


def scan_bluetooth(duration: int = 8) -> list[dict]:
    """
    Scan for nearby Bluetooth devices.
    Returns [{'name': str, 'mac': str}, ...]
    Raises BluetoothUnavailableError if hardware is not present.
    """
    return get_bluetooth().scan(duration=duration)


def send_bt(mac_or_chat_id: str, plaintext: str) -> None:
    """
    Send a plaintext message to a Bluetooth peer over RFCOMM.
    Also appends to ChatStore so the message appears in the UI.
    """
    import datetime
    bt = get_bluetooth()
    bt.send(mac_or_chat_id, plaintext)
    chat_id = mac_or_chat_id if mac_or_chat_id.upper().startswith('BT:') \
              else chat_id_from_mac(mac_or_chat_id)
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    chats.append_message(chat_id, {"token": plaintext, "sender": "me", "ts": ts})
    log.info(f"[bluetooth] sent message to {chat_id}")


def start_bt_listener() -> None:
    """
    Start the background RFCOMM listener.
    No-op if already running or if PyBluez is unavailable.
    """
    try:
        get_bluetooth().start_listener()
    except BluetoothUnavailableError as e:
        log.warning(f"[bluetooth] listener not started: {e}")


def stop_bt_listener() -> None:
    """Stop the background RFCOMM listener if running."""
    with _bt_lock:
        if _bt is not None:
            _bt.stop_listener()


# ---------------------------------------------------------------------------
# Node lifecycle (called by web.py on startup, or by 'run' CLI command)
# ---------------------------------------------------------------------------

def start_node(passphrase: str) -> Node:
    """
    Load identity, create Node, start background threads.
    Returns the Node. Safe to call only once.
    """
    global _node
    with _node_lock:
        if _node is not None:
            return _node

        if not identity.has_identity():
            raise RuntimeError("No identity found. Run: python main.py init")

        identity.load_identity(passphrase=passphrase)
        log.info("Identity loaded: " + identity.get_user_id())

        _node = Node(
            identity_manager=identity,
            config_store=config,
            peer_store=peers,
            chat_store=chats,
        )
        _node.start()
        log.info("Node started")

        # Wire node into plugin manager and enable saved plugins.
        plugin_manager.set_node(_node)
        plugin_manager.enable_all_saved()

        # Start Bluetooth listener (silently skipped if PyBluez unavailable).
        start_bt_listener()

        return _node


def stop_node():
    global _node
    with _node_lock:
        if _node:
            _node.stop()
            _node = None
            log.info("Node stopped")
    stop_bt_listener()


def get_node() -> Node | None:
    return _node


# ---------------------------------------------------------------------------
# Messaging API (used by web.py)
# ---------------------------------------------------------------------------

def send_message(peer_user_id: str, plaintext: str) -> bool:
    """
    Send a plaintext message to a peer.
    Automatically routes over Bluetooth if the chat ID starts with 'BT:'.
    Returns True on delivery.
    """
    if is_bt_chat_id(peer_user_id):
        send_bt(peer_user_id, plaintext)
        return True
    if _node is None:
        raise RuntimeError("Node not started. Call start_node() first.")
    return _node.send(peer_user_id, plaintext)


def get_messages(chat_id: str) -> list:
    """Return all stored messages for a chat."""
    return chats.load_messages(chat_id)


def get_chats() -> list:
    """Return all known chat IDs with message counts."""
    return [
        {"id": cid, "count": chats.message_count(cid)}
        for cid in chats.list_chats()
    ]


def get_peers() -> list:
    """Return all known peers."""
    return peers.all()


def get_identity_status() -> dict:
    """Return current identity info for the UI."""
    has = identity.has_identity()
    user_id = ""
    if has and identity.ed25519_priv:
        try:
            user_id = identity.get_user_id()
        except Exception:
            pass
    return {
        "has_identity": has,
        "user_id": user_id,
        "username": config.username or "",
        "node_running": _node is not None,
    }


def encrypt_message(plaintext: str, chat_id: str, created_at: str, passphrase: str) -> str:
    """
    Encrypt a message token for display/storage.

    If the identity is unlocked and the peer has an X25519 public key in
    PeerStore, use E2EManager (X25519-AES-256-GCM).  Otherwise fall back
    to the legacy CryptoManager (passphrase + AES-256-GCM).
    """
    if identity.x25519_priv is not None:
        peer_info = peers.get(chat_id)
        peer_pub  = peer_info.get("x25519_pub") if peer_info else None
        if peer_pub:
            return E2EManager(identity.x25519_priv).encrypt(
                plaintext=plaintext,
                peer_x25519_pub_b64=peer_pub,
                chat_id=chat_id,
                created_at=created_at,
            )

    # Legacy path — passphrase-based
    return CryptoManager(passphrase).encrypt(
        plaintext=plaintext,
        chat_id=chat_id,
        created_at=created_at,
    )


def decrypt_message(token: str, passphrase: str, chat_id: str | None = None) -> str:
    """
    Decrypt a message token.

    E2E tokens are decrypted with E2EManager using the local X25519 private
    key.  When the local node is the original sender (sender_pub == local_pub),
    E2EManager needs the recipient's pub key to re-derive the shared secret;
    this is looked up from PeerStore via *chat_id*.

    Legacy passphrase tokens fall back to CryptoManager.
    """
    if E2EManager.is_e2e_token(token):
        if identity.x25519_priv is None:
            raise RuntimeError(
                "Identity not unlocked — cannot decrypt E2E token. "
                "Start the node with your passphrase first."
            )
        # Look up peer pub key so the sender can re-read their own messages.
        peer_pub = None
        if chat_id:
            peer_info = peers.get(chat_id)
            peer_pub  = peer_info.get("x25519_pub") if peer_info else None
        return E2EManager(identity.x25519_priv).decrypt(
            token,
            peer_x25519_pub_b64=peer_pub,
        )

    # Legacy path
    return CryptoManager(passphrase).decrypt(token)


def configure_sms(username: str, password: str, host: str | None):
    config.set_sms_gateway(
        provider=username,
        api_key=password,
        sender_id=host or "cloud",
    )


def send_sms(to: str, message: str) -> dict:
    # Prefer plugin instance if available and configured
    plugin = plugin_manager.get("sms_gateway")
    if plugin and plugin._enabled:
        return plugin.get_sms_instance().send(to, message)
    # Fallback to legacy ConfigStore-based approach
    sms = SMSGateway.from_config(config)
    return sms.send(to, message)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    if identity.has_identity():
        print("Identity already exists.")
        return 0
    import getpass
    passphrase = getpass.getpass("Choose a passphrase: ")
    confirm    = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        print("Passphrases do not match.")
        return 1
    identity.generate_new_identity()
    identity.save_identity(passphrase=passphrase)
    if args.username:
        config.username = args.username
    print("Identity created.")
    print("User ID:", identity.get_user_id())
    return 0


def cmd_run(args):
    import getpass
    passphrase = args.passphrase or getpass.getpass("Passphrase: ")
    try:
        node = start_node(passphrase=passphrase)
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1

    print(f"Enclave node running. User ID: {identity.get_user_id()}")
    print("Press Ctrl+C to stop.")

    stop_event = threading.Event()

    def _handle_signal(sig, frame):
        print("\nShutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    stop_event.wait()
    stop_node()
    return 0


def cmd_encrypt(args):
    token = encrypt_message(
        plaintext=args.message,
        chat_id=args.chat_id,
        created_at=args.created_at,
        passphrase=args.passphrase,
    )
    print(token)
    return 0


def cmd_decrypt(args):
    try:
        plaintext = decrypt_message(args.token, args.passphrase)
        try:
            parsed = json.loads(plaintext)
            print(json.dumps(parsed, indent=2))
        except json.JSONDecodeError:
            print(plaintext)
        return 0
    except Exception as e:
        print(f"Decrypt failed: {e}", file=sys.stderr)
        return 1


def cmd_sms_config(args):
    configure_sms(args.username, args.password, args.host)
    print("SMS gateway config saved.")
    return 0


def cmd_sms_send(args):
    try:
        result = send_sms(args.to, args.message)
        print("Sent:", result)
        return 0
    except Exception as e:
        print(f"SMS gateway not configured or failed: {e}")
        return 1


def cmd_bt_scan(args):
    print("Scanning for Bluetooth devices...")
    try:
        devices = scan_bluetooth(duration=args.duration)
        if not devices:
            print("No devices found.")
            return 0
        for d in devices:
            print(f"  {d['mac']}  {d['name']}")
        return 0
    except BluetoothUnavailableError as e:
        print(f"Bluetooth unavailable: {e}")
        return 1


def cmd_bt_send(args):
    try:
        send_bt(args.to, args.message)
        print(f"Sent to {args.to}")
        return 0
    except BluetoothUnavailableError as e:
        print(f"Bluetooth unavailable: {e}")
        return 1
    except Exception as e:
        print(f"Bluetooth send failed: {e}")
        return 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(prog="enclave", description="Enclave Messenger")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="Create a new identity")
    p_init.add_argument("--username", default=None)
    p_init.set_defaults(func=cmd_init)

    # run
    p_run = sub.add_parser("run", help="Start the Enclave node (discovery + transport)")
    p_run.add_argument("--passphrase", default=None,
                       help="Identity passphrase (prompted if omitted)")
    p_run.set_defaults(func=cmd_run)

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a message")
    p_enc.add_argument("--passphrase",  required=True)
    p_enc.add_argument("--chat-id",     required=True)
    p_enc.add_argument("--created-at",  required=True)
    p_enc.add_argument("--message",     required=True)
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a message token")
    p_dec.add_argument("--passphrase", required=True)
    p_dec.add_argument("token")
    p_dec.set_defaults(func=cmd_decrypt)

    # sms
    p_sms = sub.add_parser("sms", help="SMS gateway commands")
    sms_sub = p_sms.add_subparsers(dest="sms_cmd", required=True)

    p_sms_cfg = sms_sub.add_parser("config")
    p_sms_cfg.add_argument("--username", required=True)
    p_sms_cfg.add_argument("--password", required=True)
    p_sms_cfg.add_argument("--host", default=None)
    p_sms_cfg.set_defaults(func=cmd_sms_config)

    p_sms_send = sms_sub.add_parser("send")
    p_sms_send.add_argument("--to",      required=True)
    p_sms_send.add_argument("--message", required=True)
    p_sms_send.set_defaults(func=cmd_sms_send)

    # bt
    p_bt = sub.add_parser("bt", help="Bluetooth commands")
    bt_sub = p_bt.add_subparsers(dest="bt_cmd", required=True)

    p_bt_scan = bt_sub.add_parser("scan", help="Scan for nearby Bluetooth devices")
    p_bt_scan.add_argument("--duration", type=int, default=8,
                           help="Scan duration in seconds (default: 8)")
    p_bt_scan.set_defaults(func=cmd_bt_scan)

    p_bt_send = bt_sub.add_parser("send", help="Send a message over Bluetooth")
    p_bt_send.add_argument("--to",      required=True,
                           help="Target MAC address (AA:BB:CC:DD:EE:FF) or BT: chat ID")
    p_bt_send.add_argument("--message", required=True)
    p_bt_send.set_defaults(func=cmd_bt_send)

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
