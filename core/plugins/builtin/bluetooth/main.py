"""
bluetooth/main.py — Bluetooth transport plugin for Enclave Messenger

Handles device discovery and RFCOMM message exchange.
Bluetooth chat IDs use the prefix 'BT:' followed by the device MAC address,
e.g. 'BT:AA:BB:CC:DD:EE:FF'.

Usage:
    from core.plugins.builtin.bluetooth.main import BluetoothPlugin
    bt = BluetoothPlugin()
    devices = bt.scan()          # -> [{'name': 'Phone', 'mac': 'AA:BB:CC:DD:EE:FF'}, ...]
    bt.send('AA:BB:CC:DD:EE:FF', 'Hello from Enclave!')

Scan strategy:
    1. Uses PyBluez if installed (pip install pybluez2 on Linux, PyBluez-win10 on Windows)
    2. Falls back to shelling out to bluetoothctl (Linux/BlueZ, no extra packages needed)

Note: Bluetooth hardware must be present and powered on.
If unavailable, all methods raise BluetoothUnavailableError with a clear message.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from typing import Callable

from core.plugins.base import EnclavePlugin, PluginCore

logger = logging.getLogger(__name__)

RFCOMM_PORT     = 3
SOCKET_UUID     = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
CONNECT_TIMEOUT = 10
RECV_BUFSIZE    = 4096

# ── Optional PyBluez import ───────────────────────────────────────────────────

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
            "PyBluez is not installed. "
            "On Linux: sudo apt install libbluetooth-dev && pip install pybluez2"
        )


# ── MAC helpers ──────────────────────────────────────────────────────

MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def is_bt_chat_id(chat_id: str) -> bool:
    if chat_id.upper().startswith('BT:'):
        return MAC_RE.match(chat_id[3:]) is not None
    return MAC_RE.match(chat_id) is not None


def mac_from_chat_id(chat_id: str) -> str:
    return chat_id[3:].upper() if chat_id.upper().startswith('BT:') else chat_id.upper()


def chat_id_from_mac(mac: str) -> str:
    return 'BT:' + mac.upper()


# ── Main plugin class ──────────────────────────────────────────────────

class BluetoothPlugin:
    """
    Enclave Bluetooth transport plugin.

    Thread-safe. A single background listener thread accepts inbound
    RFCOMM connections and fires the on_message callback.
    """

    def __init__(self, on_message: Callable[[str, str], None] | None = None):
        self._on_message  = on_message
        self._server_sock = None
        self._listener    = None
        self._stop_event  = threading.Event()

    # ── Discovery ─────────────────────────────────────────────────────

    def scan(self, duration: int = 8, flush_cache: bool = True) -> list[dict]:
        """
        Perform a Bluetooth device discovery.

        Strategy:
          1. PyBluez  — used if installed
          2. bluetoothctl — shell fallback (Linux/BlueZ, no extra packages)

        Returns:
            List of dicts: [{'name': str, 'mac': str}, ...]

        Raises:
            BluetoothUnavailableError: if neither method is available or HW error.
        """
        if _BT_AVAILABLE:
            logger.info("[bluetooth] scanning via PyBluez (duration=%ds)", duration)
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
            logger.info("[bluetooth] PyBluez scan done — %d device(s)", len(devices))
            return devices

        logger.info("[bluetooth] PyBluez unavailable — falling back to bluetoothctl")
        try:
            subprocess.run(
                ["bluetoothctl", "scan", "on"],
                capture_output=True, timeout=2,
            )
            time.sleep(duration)
            subprocess.run(
                ["bluetoothctl", "scan", "off"],
                capture_output=True, timeout=2,
            )
            result = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True, text=True, timeout=5,
            )
        except FileNotFoundError:
            raise BluetoothUnavailableError(
                "Neither PyBluez nor bluetoothctl is available on this system."
            )
        except subprocess.TimeoutExpired:
            raise BluetoothUnavailableError("bluetoothctl timed out during scan.")

        devices = []
        for line in result.stdout.splitlines():
            m = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if m:
                devices.append({
                    'mac':  m.group(1).upper(),
                    'name': m.group(2).strip() or 'Unknown',
                })
        logger.info("[bluetooth] bluetoothctl scan done — %d device(s)", len(devices))
        return devices

    # ── Send ──────────────────────────────────────────────────────────

    def send(self, mac_or_chat_id: str, plaintext: str) -> None:
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

    # ── Listener ──────────────────────────────────────────────────────

    def start_listener(self) -> None:
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

    @classmethod
    def from_config(cls, config, on_message=None) -> "BluetoothPlugin":
        return cls(on_message=on_message)


# ── EnclavePlugin wrapper (required by PluginManager) ─────────────────────────

class Plugin(EnclavePlugin):
    """
    EnclavePlugin wrapper around BluetoothPlugin.
    Registered by PluginManager; exposes lifecycle hooks and status.
    """

    name         = "bluetooth"
    display_name = "Bluetooth"
    description  = "Bluetooth RFCOMM transport for local peer-to-peer messaging."
    version      = "1.0.0"
    author       = "Project Enclave"

    def __init__(self):
        super().__init__()
        self._bt: BluetoothPlugin | None = None

    def enable(self, core: PluginCore) -> None:
        super().enable(core)
        self._bt = BluetoothPlugin(
            on_message=self._on_message_cb,
        )
        try:
            self._bt.start_listener()
        except BluetoothUnavailableError as e:
            logger.warning("[bluetooth:plugin] listener not started: %s", e)

    def disable(self) -> None:
        if self._bt:
            self._bt.stop_listener()
            self._bt = None
        super().disable()

    def _on_message_cb(self, chat_id: str, text: str) -> None:
        if self._core and self._core.chats:
            import datetime
            ts = datetime.datetime.utcnow().isoformat() + "Z"
            self._core.chats.append_message(
                chat_id, {"token": text, "sender": "peer", "ts": ts}
            )

    def get_status(self) -> dict:
        if not self._enabled:
            return {"ok": False, "message": "disabled"}
        if not _BT_AVAILABLE:
            return {"ok": False, "message": "PyBluez not installed"}
        return {"ok": True, "message": "listening"}

    def get_settings_schema(self) -> list[dict]:
        return [
            {
                "key": "scan_duration",
                "label": "Scan duration (seconds)",
                "type": "number",
                "required": False,
                "default": 8,
                "hint": "How long to scan for nearby Bluetooth devices.",
            }
        ]
