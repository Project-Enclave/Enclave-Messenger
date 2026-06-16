"""
manager.py — PluginManager: discovery, lifecycle, and storage for plugins.

Plugin locations:
  Builtin:        core/plugins/builtin/<id>/
  User-installed: ~/.enclave-messenger/plugins/<id>/

Each plugin folder must contain:
  manifest.json   — metadata and permissions (read before any code runs)
  main.py         — contains a class Plugin(EnclavePlugin)
"""

from __future__ import annotations

import os
import json
import importlib.util
import sys
from typing import TYPE_CHECKING

from .base import EnclavePlugin, PluginCore
from .security import PluginSecurity

if TYPE_CHECKING:
    from core.storage import ConfigStore, ChatStore, PeerStore, LogStore
    from core.identity import IdentityManager
    from core.network import Node

BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "builtin")
USER_PLUGIN_DIR = os.path.expanduser("~/.enclave-messenger/plugins")

REQUIRED_MANIFEST_KEYS = {"id", "display_name", "description", "version"}


class PluginManager:
    def __init__(
        self,
        config: "ConfigStore",
        peers: "PeerStore",
        chats: "ChatStore",
        identity: "IdentityManager",
        log: "LogStore",
    ):
        self._config = config
        self._peers = peers
        self._chats = chats
        self._identity = identity
        self._log = log
        self._node = None  # set later via set_node()

        # id -> {manifest, instance, enabled}
        self._registry: dict[str, dict] = {}

        self._security = PluginSecurity(
            config=config,
            log=log,
            disable_callback=self._auto_disable,
        )

        os.makedirs(USER_PLUGIN_DIR, exist_ok=True)
        self._drop_user_readme()

    def set_node(self, node):
        """Call after Node is started so network-permission plugins can receive it."""
        self._node = node

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self):
        """Scan builtin and user plugin directories, register all valid plugins."""
        # Builtins first so their IDs are reserved
        self._scan_dir(BUILTIN_DIR, builtin=True)
        self._scan_dir(USER_PLUGIN_DIR, builtin=False)
        self._log.info(f"Plugins discovered: {list(self._registry.keys())}")

    def _scan_dir(self, directory: str, builtin: bool):
        if not os.path.isdir(directory):
            return
        for entry in os.scandir(directory):
            if not entry.is_dir():
                continue
            self._load_plugin_folder(entry.path, builtin=builtin)

    def _load_plugin_folder(self, folder: str, builtin: bool):
        manifest_path = os.path.join(folder, "manifest.json")
        main_path = os.path.join(folder, "main.py")

        # Read manifest before touching any Python
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as e:
            self._log.warning(f"[plugins] Skipping {folder}: manifest error: {e}")
            return

        missing = REQUIRED_MANIFEST_KEYS - manifest.keys()
        if missing:
            self._log.warning(f"[plugins] Skipping {folder}: manifest missing {missing}")
            return

        plugin_id = manifest["id"]

        # Builtins reserve their IDs
        if plugin_id in self._registry:
            existing = self._registry[plugin_id]
            if existing.get("builtin") and not builtin:
                self._log.warning(f"[plugins] User plugin '{plugin_id}' conflicts with builtin — skipped")
                return

        if not os.path.exists(main_path):
            self._log.warning(f"[plugins] Skipping {folder}: missing main.py")
            return

        # Import the plugin module
        try:
            spec = importlib.util.spec_from_file_location(f"enclave_plugin_{plugin_id}", main_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"enclave_plugin_{plugin_id}"] = mod
            spec.loader.exec_module(mod)
            plugin_class = getattr(mod, "Plugin", None)
            if plugin_class is None or not issubclass(plugin_class, EnclavePlugin):
                raise ValueError("main.py must define a class Plugin(EnclavePlugin)")
            instance = plugin_class()
        except Exception as e:
            self._log.error(f"[plugins] Failed to load {folder}: {e}")
            return

        self._registry[plugin_id] = {
            "manifest": manifest,
            "instance": instance,
            "builtin": builtin,
            "folder": folder,
        }
        self._log.info(f"[plugins] Registered {'builtin' if builtin else 'user'} plugin: {plugin_id}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def enable_all_saved(self):
        """On startup: enable all plugins that were enabled in the last session."""
        plugins_cfg = self._config.get("plugins", {}) or {}
        for plugin_id, state in plugins_cfg.items():
            if state.get("enabled") and not state.get("auto_disabled"):
                self.enable(plugin_id, _startup=True)

    def enable(self, plugin_id: str, _startup: bool = False) -> dict:
        """Enable a plugin. Returns result dict with ok/error."""
        entry = self._registry.get(plugin_id)
        if entry is None:
            return {"ok": False, "error": "Plugin not found"}

        manifest = entry["manifest"]
        instance: EnclavePlugin = entry["instance"]

        # Build scoped core
        core = self._security.build_core(manifest, {
            "config": self._config,
            "peers": self._peers,
            "chats": self._chats,
            "identity": self._identity,
            "node": self._node,
        })

        # Wrap enable() in watchdog
        safe_enable = self._security.wrap(plugin_id, instance.enable, "enable")
        safe_enable(core)

        # Persist enabled state
        self._security.clear_auto_disable(plugin_id)
        self._set_enabled(plugin_id, True)
        self._log.info(f"[plugins] Enabled: {plugin_id}")
        return {"ok": True}

    def disable(self, plugin_id: str) -> dict:
        """Disable a plugin (user-initiated)."""
        entry = self._registry.get(plugin_id)
        if entry is None:
            return {"ok": False, "error": "Plugin not found"}

        instance: EnclavePlugin = entry["instance"]
        safe_disable = self._security.wrap(plugin_id, instance.disable, "disable")
        safe_disable()

        self._set_enabled(plugin_id, False)
        self._log.info(f"[plugins] Disabled: {plugin_id}")
        return {"ok": True}

    def _auto_disable(self, plugin_id: str, reason: str):
        """Called by PluginSecurity watchdog on threshold breach."""
        entry = self._registry.get(plugin_id)
        if entry:
            try:
                entry["instance"].disable()
            except Exception:
                pass
        self._set_enabled(plugin_id, False)
        self._security.record_auto_disable(plugin_id, reason)
        self._log.error(f"[plugins] Auto-disabled {plugin_id}: {reason}")

    def configure(self, plugin_id: str, settings: dict) -> dict:
        entry = self._registry.get(plugin_id)
        if entry is None:
            return {"ok": False, "error": "Plugin not found"}
        instance: EnclavePlugin = entry["instance"]
        safe_configure = self._security.wrap(plugin_id, instance.configure, "configure")
        safe_configure(settings)
        # Persist settings
        plugins_cfg = self._config.get("plugins", {}) or {}
        if plugin_id not in plugins_cfg:
            plugins_cfg[plugin_id] = {}
        plugins_cfg[plugin_id]["settings"] = settings
        self._config.set("plugins", plugins_cfg)
        return {"ok": True}

    def set_override(self, plugin_id: str, override: bool) -> dict:
        """Set or clear the user security override for a plugin."""
        if plugin_id not in self._registry:
            return {"ok": False, "error": "Plugin not found"}
        self._security.set_user_override(plugin_id, override)
        return {"ok": True}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_all(self) -> list[dict]:
        """Return a list of plugin info dicts for the API."""
        result = []
        plugins_cfg = self._config.get("plugins", {}) or {}
        for plugin_id, entry in self._registry.items():
            manifest = entry["manifest"]
            instance: EnclavePlugin = entry["instance"]
            state = plugins_cfg.get(plugin_id, {})
            security_info = self._security.get_security_info(plugin_id)
            safe_status = self._security.wrap(plugin_id, instance.get_status, "get_status")
            status = safe_status() or {"ok": False}
            result.append({
                "id": plugin_id,
                "display_name": manifest.get("display_name", plugin_id),
                "description": manifest.get("description", ""),
                "version": manifest.get("version", ""),
                "author": manifest.get("author", "Unknown"),
                "permissions": manifest.get("permissions", []),
                "builtin": entry["builtin"],
                "enabled": bool(state.get("enabled")) and not security_info["auto_disabled"],
                "settings": state.get("settings", {}),
                "schema": instance.get_settings_schema(),
                "status": status,
                "security": security_info,
            })
        return result

    def get(self, plugin_id: str) -> EnclavePlugin | None:
        entry = self._registry.get(plugin_id)
        return entry["instance"] if entry else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_enabled(self, plugin_id: str, enabled: bool):
        plugins_cfg = self._config.get("plugins", {}) or {}
        if plugin_id not in plugins_cfg:
            plugins_cfg[plugin_id] = {}
        plugins_cfg[plugin_id]["enabled"] = enabled
        self._config.set("plugins", plugins_cfg)

    def _drop_user_readme(self):
        readme = os.path.join(USER_PLUGIN_DIR, "README.md")
        if os.path.exists(readme):
            return
        content = """# Enclave User Plugins

Drop plugin folders here. Each plugin must contain:

```
my_plugin/
    manifest.json
    main.py
```

## manifest.json

```json
{
    "id": "my_plugin",
    "display_name": "My Plugin",
    "description": "What it does.",
    "version": "1.0.0",
    "author": "You",
    "min_enclave_version": "1.0.0",
    "permissions": ["config"]
}
```

## Permissions

| Permission | Grants access to |
|---|---|
| `config`   | Plugin's own config section |
| `peers`    | Peer list (read) |
| `chats`    | Chat history (read/write) |
| `identity` | Your user ID and public key (read-only, no private keys) |
| `network`  | Send messages, register inbound callbacks |

## main.py

```python
from core.plugins.base import EnclavePlugin, PluginCore

class Plugin(EnclavePlugin):
    name = "my_plugin"
    display_name = "My Plugin"
    description = "What it does."
    version = "1.0.0"
    author = "You"

    def enable(self, core: PluginCore):
        super().enable(core)
        # your startup code here

    def disable(self):
        super().disable()
        # your teardown code here

    def get_settings_schema(self):
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "default": ""},
        ]

    def configure(self, settings):
        # save settings via self._core.config if needed
        pass

    def get_status(self):
        return {"ok": True, "message": "Running"}
```

## Warning

Plugins run with the same permissions as Enclave itself.
Only install plugins from sources you trust.
"""
        try:
            with open(readme, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError:
            pass
