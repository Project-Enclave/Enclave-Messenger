"""
test_sms_gateway.py — tests for the SMS gateway: the pure host:port
parser, from_config() construction, request construction (mocked HTTP —
there's no real android-sms-gateway device to test against), and the
plugin wrapper's get_sms_instance(), which had a broken import
(core.plugins.sms_gateway instead of
core.plugins.builtin.sms_gateway.sms_gateway) that nothing had ever
caught because nothing in web.py currently enables the plugin at all —
only the legacy /api/sms/* routes (SMSGateway.from_config() directly)
are reachable through the actual product today.

Run: python3 test_sms_gateway.py
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.plugins.builtin.sms_gateway.sms_gateway import SMSGateway, _parse_host_port
from core.plugins.builtin.sms_gateway.main import Plugin as SMSPlugin
from core.plugins.manager import PluginManager
from core.storage import ConfigStore, ChatStore, PeerStore
from core.identity.key_manager import IdentityManager

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def test_parse_host_port():
    check("bare host uses default port", _parse_host_port("192.168.1.5", 8080) == ("192.168.1.5", 8080))
    check("host:port uses the embedded port", _parse_host_port("192.168.1.5:9000", 8080) == ("192.168.1.5", 9000))
    check("whitespace is stripped", _parse_host_port(" 192.168.1.5 : 9000 ", 8080) == ("192.168.1.5", 9000))
    check("non-numeric port falls back to default",
          _parse_host_port("192.168.1.5:notaport", 8080) == ("192.168.1.5:notaport", 8080))


def test_gateway_construction():
    gw = SMSGateway(username="u", password="p", host="192.168.1.5:9000")
    check("local mode builds the correct base_url", gw.base_url == "http://192.168.1.5:9000")

    gw2 = SMSGateway(username="u", password="p", use_cloud=True)
    check("cloud mode uses the cloud URL", gw2.base_url == "https://api.sms-gate.app/3rdparty/v1")

    try:
        SMSGateway(username="u", password="p", use_cloud=False, host=None)
        check("local mode without a host raises", False)
    except ValueError:
        check("local mode without a host raises", True)


def test_from_config():
    tmp_cfg = ConfigStore(base_dir="/tmp/enclave_sms_test_cfg")
    tmp_cfg.set_sms_gateway(provider="myuser", api_key="mypass", sender_id="192.168.1.9:8080")
    gw = SMSGateway.from_config(tmp_cfg)
    check("from_config builds local mode from a real ConfigStore",
          gw.username == "myuser" and gw.base_url == "http://192.168.1.9:8080")

    tmp_cfg.set_sms_gateway(provider="myuser", api_key="mypass", sender_id="cloud")
    gw2 = SMSGateway.from_config(tmp_cfg)
    check("from_config('cloud') builds cloud mode", gw2.use_cloud is True)


def test_send_request_construction():
    """
    Mocks requests.post — there's no real gateway device to send to, but
    this verifies SMSGateway.send() builds the correct URL/payload/auth,
    which is the part that's actually ours to get right.
    """
    gw = SMSGateway(username="u", password="p", host="192.168.1.5:8080")
    with patch("core.plugins.builtin.sms_gateway.sms_gateway.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200,
                                            json=lambda: {"id": "msg1", "state": "Pending"})
        mock_post.return_value.raise_for_status = lambda: None
        result = gw.send("+15551234567", "hello")

    call = mock_post.call_args
    check("send() POSTs to the correct /message endpoint",
          call.args[0] == "http://192.168.1.5:8080/message")
    check("send() sends the phone number as a list", call.kwargs["json"]["phoneNumbers"] == ["+15551234567"])
    check("send() sends the message text correctly", call.kwargs["json"]["textMessage"]["text"] == "hello")
    check("send() uses HTTP basic auth with the configured credentials",
          call.kwargs["auth"].username == "u" and call.kwargs["auth"].password == "p")
    check("send() returns the parsed response", result == {"id": "msg1", "state": "Pending"})


def test_plugin_wrapper():
    """
    The bug: get_sms_instance() imported from a module path that doesn't
    exist. Confirmed unreachable through the actual web UI today (no
    /api/plugins/* routes exist to enable this plugin at all — see
    main.py's send_sms(), which only takes this path when
    plugin._enabled is True) — but it IS what main.py's send_sms() tries
    first whenever a plugin manager has it enabled (e.g. via the CLI /
    config file directly), so the broken import was a real, live bug on
    a reachable path, not purely theoretical.
    """
    cfg = ConfigStore(base_dir="/tmp/enclave_sms_test_plugin")
    chats = ChatStore(base_dir="/tmp/enclave_sms_test_plugin")
    peers = PeerStore(base_dir="/tmp/enclave_sms_test_plugin")
    im = IdentityManager(storage_dir="/tmp/enclave_sms_test_plugin/identity")
    im.generate_new_identity()

    pm = PluginManager(config=cfg, peers=peers, chats=chats, identity=im,
                        log=__import__("logging").getLogger("test"))
    pm.discover()
    check("sms_gateway plugin is discovered", "sms_gateway" in pm._registry)

    result = pm.enable("sms_gateway")
    check("sms_gateway plugin enables successfully", result.get("ok") is True)

    plugin = pm.get("sms_gateway")
    check("plugin is retrievable and enabled", plugin is not None and plugin._enabled)

    plugin.configure({"username": "bob", "password": "secret", "host": "10.0.0.5:8080"})

    # This is the exact call that used to raise ModuleNotFoundError.
    try:
        instance = plugin.get_sms_instance()
        check("get_sms_instance() no longer raises ModuleNotFoundError", True)
        check("get_sms_instance() returns a correctly configured SMSGateway",
              isinstance(instance, SMSGateway) and instance.username == "bob"
              and instance.base_url == "http://10.0.0.5:8080")
    except ModuleNotFoundError as e:
        check("get_sms_instance() no longer raises ModuleNotFoundError", False)
        print(f"    (still broken: {e})")


def test_bluetooth_chat_id_helpers():
    """
    Pure, hardware-independent logic — the only part of the bluetooth
    plugin testable without a real adapter (PyBluez isn't even installed
    in this environment). Already exercised indirectly through
    classify_address() in test_security_fixes.py; testing directly here
    too since nothing in the repo tested these functions on their own.
    """
    from core.plugins.builtin.bluetooth.main import is_bt_chat_id, chat_id_from_mac, mac_from_chat_id

    check("a raw MAC is recognized as a bt chat id",
          is_bt_chat_id("AA:BB:CC:DD:EE:FF"))
    check("a BT:-prefixed MAC is recognized as a bt chat id",
          is_bt_chat_id("BT:AA:BB:CC:DD:EE:FF"))
    check("a lowercase MAC is recognized as a bt chat id",
          is_bt_chat_id("aa:bb:cc:dd:ee:ff"))
    check("a node id is NOT recognized as a bt chat id", not is_bt_chat_id("a" * 43))
    check("garbage is NOT recognized as a bt chat id", not is_bt_chat_id("not-a-mac-at-all"))

    check("chat_id_from_mac normalizes to uppercase with BT: prefix",
          chat_id_from_mac("aa:bb:cc:dd:ee:ff") == "BT:AA:BB:CC:DD:EE:FF")
    check("chat_id_from_mac is idempotent on an already-prefixed MAC",
          chat_id_from_mac("BT:AA:BB:CC:DD:EE:FF") == "BT:AA:BB:CC:DD:EE:FF")

    check("mac_from_chat_id strips the prefix", mac_from_chat_id("BT:AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF")
    check("mac_from_chat_id passes through a bare MAC unchanged",
          mac_from_chat_id("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF")

    check("round-trip: chat_id_from_mac(mac_from_chat_id(x)) == chat_id_from_mac(x)",
          chat_id_from_mac(mac_from_chat_id("BT:aa:bb:cc:dd:ee:ff")) == chat_id_from_mac("aa:bb:cc:dd:ee:ff"))


def main():
    test_parse_host_port()
    test_gateway_construction()
    test_from_config()
    test_send_request_construction()
    test_plugin_wrapper()
    test_bluetooth_chat_id_helpers()

    import shutil
    for d in ("/tmp/enclave_sms_test_cfg", "/tmp/enclave_sms_test_plugin"):
        shutil.rmtree(d, ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
