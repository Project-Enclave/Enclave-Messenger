import os
import json
import tempfile

from core.storage.config_store import ConfigStore
from core.storage.chat_store import ChatStore


def test_config_store(tmp_path):
    base = tmp_path / "storage"
    cs = ConfigStore(base_dir=str(base))

    # Defaults present
    assert cs.get_setting("port") == 5000

    cs.set("username", "alice")
    assert cs.username == "alice"

    cs.set_sms_gateway("prov", "key", "cloud")
    gw = cs.get_sms_gateway()
    assert gw["provider"] == "prov"


def test_chat_store_append_and_load(tmp_path):
    base = tmp_path / "storage"
    cs = ChatStore(base_dir=str(base))

    chat_id = "chat/1"
    assert cs.has_chat(chat_id) is False

    cs.append_message(chat_id, {"token": "t1", "sender": "me", "ts": "now"})
    msgs = cs.load_messages(chat_id)
    assert len(msgs) == 1
    assert msgs[0]["token"] == "t1"

    # Legacy append string
    cs.append_message(chat_id, "t2")
    msgs = cs.load_messages(chat_id)
    assert any(m["token"] == "t2" for m in msgs)

    # Delete
    assert cs.delete_chat(chat_id) is True
    assert cs.has_chat(chat_id) is False
