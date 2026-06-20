from core.plugins.builtin.bluetooth.main import (
    is_bt_chat_id,
    mac_from_chat_id,
    chat_id_from_mac,
    MAC_RE,
)


def test_is_bt_chat_id_with_prefix():
    assert is_bt_chat_id("BT:AA:BB:CC:DD:EE:FF") is True
    assert is_bt_chat_id("BT:aa:bb:cc:dd:ee:ff") is True


def test_is_bt_chat_id_without_prefix():
    assert is_bt_chat_id("AA:BB:CC:DD:EE:FF") is True
    assert is_bt_chat_id("invalid-mac") is False


def test_mac_from_chat_id_and_back():
    assert mac_from_chat_id("BT:aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert mac_from_chat_id("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert chat_id_from_mac("aa:bb:cc:dd:ee:ff") == "BT:AA:BB:CC:DD:EE:FF"


def test_mac_regex():
    assert MAC_RE.match("AA:BB:CC:DD:EE:FF") is not None
    assert MAC_RE.match("AA:BB:CC") is None
