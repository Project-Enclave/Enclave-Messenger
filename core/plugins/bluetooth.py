"""
bluetooth.py — Bluetooth transport plugin for Enclave Messenger

Handles device discovery and RFCOMM message exchange using PyBluez.
Bluetooth chat IDs use the prefix 'BT:' followed by the device MAC address,
e.g. 'BT:AA:BB:CC:DD:EE:FF'.

Usage:
    from core.plugins.bluetooth import BluetoothPlugin
    bt = BluetoothPlugin()
    devices = bt.scan()          # -> [{'name': 'Phone', 'mac': 'AA:BB:CC:DD:EE:FF'}, ...]
    bt.send('AA:BB:CC:DD:EE:FF', 'Hello from Enclave!')

Requires:
    pip install PyBluez
    On Linux: sudo apt install libbluetooth-dev

Note: Bluetooth hardware must be present and powered on.
If unavailable, all methods raise BluetoothUnavailableError with a clear message.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Callable

logger = logging.getLogger(__name__)

RFCOMM_PORT  = 3        # RFCOMM channel used by Enclave
SOCKET_UUID  = "94f39d29-7d6d-437d-973b-fba39e49d4ee"  # Enclave SDP service UUID
CONNECT_TIMEOUT = 10   # seconds
RECV_BUFSIZE    = 4096

# ── Sentinel for graceful import failure ─────────────────────────────────────

try:
    import bluetooth as _bt
    _BT_AVAILABLE = True
except ImportError:
    _bt = None
    _BT_AVAILABLE = False


class BluetoothUnavailableError(RuntimeError):
    """Raised when the Bluetooth stack or hardware is not usable."""


def _require_bt():
    if not _BT_AVAILABLE:
        raise BluetoothUnavailableError(
            "PyBluez is not installed. Run: pip install PyBluez"
        )


# ── MAC helpers ───────────────────────────────────────────────────────────────

MAC_RE = __import__('re').compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def is_bt_chat_id(chat_id: str) -> bool:
    """Return True if chat_id looks like a Bluetooth chat (BT:MAC or raw MAC)."""
    if chat_id.upper().startswith('BT:'):
        return MAC_RE.match(chat_id[3:]) is not None
    return MAC_RE.match(chat_id) is not None


def mac_from_chat_id(chat_id: str) -> str:
    """Extract the raw MAC address from a chat ID."""
    return chat_id[3:].upper() if chat_id.upper().startswith('BT:') else chat_id.upper()


def chat_id_from_mac(mac: str) -> str:
    """Build the canonical chat_id from a MAC address."""
    return 'BT:' + mac.upper()


# ── Main plugin class ─────────────────────────────────────────────────────────

class BluetoothPlugin:
    """
    Enclave Bluetooth transport plugin.

    Thread-safe. A single background listener thread accepts inbound
    RFCOMM connections and fires the on_message callback.
    """

    def __init__(self, on_message: Callable[[str, str], None] | None = None):
        """
        Args:
            on_message: Optional callback called when a message arrives.
                        Signature: on_message(chat_id: str, plaintext: str)
        """
        self._on_message   = on_message
        self._server_sock  = None
        self._listener     = None
        self._stop_event   = threading.Event()

    # ── Discovery ─────────────────────────────────────────────────────────────

    def scan(self, duration: int = 8, flush_cache: bool = True) -> list[dict]:
        """
        Perform a Bluetooth device discovery.

        Args:
            duration:    Inquiry duration in seconds (multiples of ~1.28 s).
            flush_cache: Whether to flush the device cache before scanning.

        Returns:
            List of dicts: [{'name': str, 'mac': str}, ...]
            Returns empty list if no devices found.

        Raises:
            BluetoothUnavailableError: If PyBluez is not installed.
        """
        _require_bt()
        logger.info("[bluetooth] starting scan (duration=%ds)", duration)
        try:
            nearby = _bt.discover_devices(
                duration=duration,
                flush_cache=flush_cache,
                lookup_names=True,
            )
        except OSError as e:
            raise BluetoothUnavailableError(
                f"Bluetooth hardware error during scan: {e}"
            ) from e

        devices = [
            {'name': name or 'Unknown', 'mac': mac.upper()}
            for mac, name in nearby
        ]
        logger.info("[bluetooth] scan complete — %d device(s) found", len(devices))
        return devices

    # ── Send ──────────────────────────────────────────────────────────────────

    def send(self, mac_or_chat_id: str, plaintext: str) -> None:
        """
        Send a plaintext message to a Bluetooth peer over RFCOMM.

        Args:
            mac_or_chat_id: Raw MAC ('AA:BB:...') or Enclave chat ID ('BT:AA:BB:...').
            plaintext:      The message text to send.

        Raises:
            BluetoothUnavailableError: Hardware or stack not available.
            bluetooth.BluetoothError:  Connection or send failure.
        """
        _require_bt()
        mac = mac_from_chat_id(mac_or_chat_id)
        sock = _bt.BluetoothSocket(_bt.RFCOMM)
        try:
            sock.connect((mac, RFCOMM_PORT))
            payload = json.dumps({'msg': plaintext}).encode()
            sock.send(payload)
            logger.info("[bluetooth] sent %d bytes to %s", len(payload), mac)
        finally:
            sock.close()

    # ── Listener ──────────────────────────────────────────────────────────────

    def start_listener(self) -> None:
        """
        Start a background RFCOMM server that accepts inbound messages.
        The on_message callback will be fired for each received message.

        Safe to call multiple times — no-op if already running.
        """
        _require_bt()
        if self._listener and self._listener.is_alive():
            return
        self._stop_event.clear()
        self._listener = threading.Thread(
            target=self._listen_loop,
            name='bt-listener',
            daemon=True,
        )
        self._listener.start()
        logger.info("[bluetooth] listener started on RFCOMM channel %d", RFCOMM_PORT)

    def stop_listener(self) -> None:
        """Signal the background listener to stop and wait for it."""
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._listener:
            self._listener.join(timeout=3)
        logger.info("[bluetooth] listener stopped")

    def _listen_loop(self) -> None:
        """Internal RFCOMM accept loop (runs in daemon thread)."""
        try:
            self._server_sock = _bt.BluetoothSocket(_bt.RFCOMM)
            self._server_sock.bind(('', RFCOMM_PORT))
            self._server_sock.listen(1)
            _bt.advertise_service(
                self._server_sock,
                'EnclaveMessenger',
                service_id=SOCKET_UUID,
                service_classes=[SOCKET_UUID, _bt.SERIAL_PORT_CLASS],
                profiles=[_bt.SERIAL_PORT_PROFILE],
            )
        except OSError as e:
            logger.error("[bluetooth] failed to start server: %s", e)
            return

        while not self._stop_event.is_set():
            try:
                self._server_sock.settimeout(1.0)
                try:
                    client_sock, client_info = self._server_sock.accept()
                except _bt.btcommon.BluetoothError:
                    continue

                mac = client_info[0].upper()
                logger.debug("[bluetooth] connection from %s", mac)
                try:
                    data = client_sock.recv(RECV_BUFSIZE)
                    payload = json.loads(data.decode())
                    text = payload.get('msg', data.decode())
                    if callable(self._on_message):
                        self._on_message(chat_id_from_mac(mac), text)
                except Exception as e:
                    logger.warning("[bluetooth] recv error from %s: %s", mac, e)
                finally:
                    client_sock.close()
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error("[bluetooth] listener loop error: %s", e)

    # ── from_config factory ───────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config, on_message=None) -> "BluetoothPlugin":
        """
        Build a BluetoothPlugin instance from a ConfigStore object.
        Config is currently not required for Bluetooth, but the factory
        method keeps the pattern consistent with other plugins.
        """
        return cls(on_message=on_message)
