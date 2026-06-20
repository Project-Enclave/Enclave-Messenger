import os
import json
import tempfile
from unittest.mock import Mock

import pytest

from core.plugins.manager import PluginManager, BUILTIN_DIR
from core.plugins.base import EnclavePlugin, PluginCore
from core.storage.config_store import ConfigStore
from core.storage.chat_store import ChatStore


class DummyLog:
    def info(self, *a, **k):
        pass
    def warning(self, *a, **k):
        pass
    def error(self, *a, **k):
        pass


class DummyPlugin(EnclavePlugin):
    name = "dummy"
    def get_status(self):
        return {"ok": True}


def make_dummy_plugin_dir(tmp_path, plugin_id, builtin=True):
    folder = tmp_path / plugin_id
    folder.mkdir()
    manifest = {
        "id": plugin_id,
        "display_name": plugin_id,
        "description": "desc",
        "version": "1.0.0",
    }
    (folder / "manifest.json").write_text(json.dumps(manifest))
    # main.py implementing Plugin
    main_py = f"from core.plugins.base import EnclavePlugin\nclass Plugin(EnclavePlugin):\n    name=\"{plugin_id}\"\n    def get_status(self):\n        return {{'ok': True}}\n"
    (folder / "main.py").write_text(main_py)
    return str(folder)


def test_plugin_manager_discover_enable_disable(tmp_path, monkeypatch):
    # Prepare a fake builtin dir
    fake_builtin = tmp_path / "builtin"
    fake_builtin.mkdir()
    plugin_dir = make_dummy_plugin_dir(fake_builtin, "plug1")

    # Monkeypatch BUILTIN_DIR to our fake dir
    monkeypatch.setattr("core.plugins.manager.BUILTIN_DIR", str(fake_builtin))
    # Ensure user plugin dir points to tmp to avoid touching home
    monkeypatch.setattr("core.plugins.manager.USER_PLUGIN_DIR", str(tmp_path / "user_plugins"))

    cs = ConfigStore(base_dir=str(tmp_path / "storage"))
    pe = Mock()
    ch = ChatStore(base_dir=str(tmp_path / "storage"))
    im = Mock()
    log = DummyLog()

    pm = PluginManager(config=cs, peers=pe, chats=ch, identity=im, log=log)
    pm.discover()

    all_plugins = pm.get_all()
    assert any(p["id"] == "plug1" for p in all_plugins)

    res = pm.enable("plug1")
    assert res["ok"] is True

    res2 = pm.disable("plug1")
    assert res2["ok"] is True
