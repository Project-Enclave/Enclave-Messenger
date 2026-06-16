"""
security.py — Plugin scope enforcement and runtime watchdog.

Responsibilities:
  1. Build a PluginCore scoped to the permissions declared in manifest.json.
  2. Wrap plugin lifecycle calls in a watchdog that catches exceptions,
     measures duration, and auto-disables misbehaving plugins.
  3. Record violations and support user override of auto-disable.
"""

from __future__ import annotations

import time
import threading
import traceback
from datetime import datetime, timezone
from typing import Callable, TYPE_CHECKING

from .base import PluginCore, ReadOnlyIdentity

if TYPE_CHECKING:
    from core.storage import ConfigStore

# Thresholds
_MAX_CONSECUTIVE_ERRORS = 3
_WARN_DURATION_S = 5.0
_AUTO_DISABLE_DURATION_S = 30.0


class PluginSecurity:
    """
    Instantiated once by PluginManager. Holds violation state for all plugins.
    """

    def __init__(self, config: "ConfigStore", log, disable_callback: Callable[[str, str], None]):
        """
        Args:
            config:           ConfigStore for persisting violation data.
            log:              LogStore for writing security events.
            disable_callback: Called with (plugin_id, reason) when auto-disabling.
        """
        self._config = config
        self._log = log
        self._disable_cb = disable_callback
        # In-memory consecutive error counters (reset on successful call)
        self._error_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Scope enforcement
    # ------------------------------------------------------------------

    def build_core(self, manifest: dict, full_core_kwargs: dict) -> PluginCore:
        """
        Build a PluginCore containing only the attributes permitted by
        the plugin's declared permissions.

        full_core_kwargs keys: config, peers, chats, identity, node
        """
        perms = set(manifest.get("permissions", []))

        return PluginCore(
            config=full_core_kwargs.get("config") if "config" in perms else None,
            peers=full_core_kwargs.get("peers") if "peers" in perms else None,
            chats=full_core_kwargs.get("chats") if "chats" in perms else None,
            identity=ReadOnlyIdentity(full_core_kwargs["identity"]) if "identity" in perms else None,
            node=full_core_kwargs.get("node") if "network" in perms else None,
        )

    # ------------------------------------------------------------------
    # Watchdog wrapper
    # ------------------------------------------------------------------

    def wrap(self, plugin_id: str, fn: Callable, method_name: str) -> Callable:
        """
        Return a wrapped version of `fn` that:
          - Catches all exceptions and records them as violations
          - Measures wall-clock duration and records slow calls
          - Auto-disables the plugin on threshold breach
        """
        def _wrapped(*args, **kwargs):
            start = time.monotonic()
            try:
                result = fn(*args, **kwargs)
                elapsed = time.monotonic() - start
                self._error_counts[plugin_id] = 0  # reset on success
                if elapsed >= _AUTO_DISABLE_DURATION_S:
                    reason = f"{method_name}() blocked for {elapsed:.1f}s (limit {_AUTO_DISABLE_DURATION_S}s)"
                    self._record_violation(plugin_id, reason)
                    if not self.is_user_overridden(plugin_id):
                        self._disable_cb(plugin_id, reason)
                elif elapsed >= _WARN_DURATION_S:
                    self._log.warning(f"[plugin:{plugin_id}] {method_name}() slow ({elapsed:.1f}s)")
                return result
            except Exception:
                elapsed = time.monotonic() - start
                tb = traceback.format_exc()
                self._error_counts[plugin_id] = self._error_counts.get(plugin_id, 0) + 1
                count = self._error_counts[plugin_id]
                reason = f"{method_name}() raised exception ({count} in a row): {tb.splitlines()[-1]}"
                self._record_violation(plugin_id, reason)
                self._log.error(f"[plugin:{plugin_id}] {reason}\n{tb}")
                if count >= _MAX_CONSECUTIVE_ERRORS and not self.is_user_overridden(plugin_id):
                    self._disable_cb(plugin_id, f"{method_name}() failed {count} times in a row")
                return None
        return _wrapped

    # ------------------------------------------------------------------
    # Violation log
    # ------------------------------------------------------------------

    def _get_plugin_state(self, plugin_id: str) -> dict:
        plugins = self._config.get("plugins", {})
        return plugins.get(plugin_id, {})

    def _save_plugin_state(self, plugin_id: str, state: dict):
        plugins = self._config.get("plugins", {}) or {}
        plugins[plugin_id] = state
        self._config.set("plugins", plugins)

    def _record_violation(self, plugin_id: str, reason: str):
        state = self._get_plugin_state(plugin_id)
        violations = state.get("violations", [])
        violations.append({
            "reason": reason,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        # Keep last 20 violations only
        state["violations"] = violations[-20:]
        state["last_violation"] = reason
        self._save_plugin_state(plugin_id, state)

    def record_auto_disable(self, plugin_id: str, reason: str):
        """Called by PluginManager after auto-disabling."""
        state = self._get_plugin_state(plugin_id)
        state["auto_disabled"] = True
        state["auto_disable_reason"] = reason
        state["auto_disable_ts"] = datetime.now(timezone.utc).isoformat()
        self._save_plugin_state(plugin_id, state)

    def clear_auto_disable(self, plugin_id: str):
        """Called when user re-enables a plugin."""
        state = self._get_plugin_state(plugin_id)
        state["auto_disabled"] = False
        state["auto_disable_reason"] = None
        self._save_plugin_state(plugin_id, state)

    def set_user_override(self, plugin_id: str, override: bool):
        """Set or clear the user override flag."""
        state = self._get_plugin_state(plugin_id)
        state["user_override"] = override
        self._save_plugin_state(plugin_id, state)

    def is_user_overridden(self, plugin_id: str) -> bool:
        return bool(self._get_plugin_state(plugin_id).get("user_override", False))

    def get_security_info(self, plugin_id: str) -> dict:
        """Return security state for the UI."""
        state = self._get_plugin_state(plugin_id)
        return {
            "auto_disabled": state.get("auto_disabled", False),
            "auto_disable_reason": state.get("auto_disable_reason"),
            "auto_disable_ts": state.get("auto_disable_ts"),
            "user_override": state.get("user_override", False),
            "violations": state.get("violations", []),
            "last_violation": state.get("last_violation"),
        }
