"""
base.py — EnclavePlugin base class and PluginCore scoped context.

All plugins (builtin or user-installed) must subclass EnclavePlugin
and implement the required attributes and methods.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.storage import ConfigStore, ChatStore, PeerStore
    from core.network import Node
    from core.identity import IdentityManager


class ReadOnlyIdentity:
    """
    A read-only proxy for IdentityManager.
    Plugins only ever see the public user ID and public key —
    private keys are never exposed.
    """
    def __init__(self, identity_manager):
        self._im = identity_manager

    def get_user_id(self) -> str:
        return self._im.get_user_id()

    def get_public_key(self) -> str:
        """Return the Ed25519 public key as a base64url string."""
        from cryptography.hazmat.primitives import serialization
        import base64
        pub_bytes = self._im.ed25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.urlsafe_b64encode(pub_bytes).decode("utf-8").rstrip("=")


class PluginCore:
    """
    Scoped context object passed to plugins on enable().
    Attributes are None if the plugin did not declare the corresponding permission.
    Built by PluginSecurity.build_core() — never instantiated directly by plugins.
    """
    def __init__(
        self,
        config=None,
        peers=None,
        chats=None,
        identity: ReadOnlyIdentity | None = None,
        node=None,
    ):
        self.config = config    # requires: "config"
        self.peers = peers      # requires: "peers"
        self.chats = chats      # requires: "chats"
        self.identity = identity  # requires: "identity"
        self.node = node        # requires: "network"


class EnclavePlugin:
    """
    Base class for all Enclave plugins.

    Subclass this and set the class-level attributes, then implement
    enable(), disable(), get_settings_schema(), and configure().

    The plugin's main.py must expose a single subclass of EnclavePlugin
    at module level as `Plugin`.

    Example manifest.json:
        {
            "id": "my_plugin",
            "display_name": "My Plugin",
            "description": "Does something useful.",
            "version": "1.0.0",
            "author": "You",
            "min_enclave_version": "1.0.0",
            "permissions": ["config"]
        }
    """

    # --- Required class attributes (set on your subclass) ---
    name: str = ""
    display_name: str = ""
    description: str = ""
    version: str = "0.0.0"
    author: str = ""

    def __init__(self):
        self._core: PluginCore | None = None
        self._enabled: bool = False

    # --- Lifecycle ---

    def enable(self, core: PluginCore) -> None:
        """
        Called when the plugin is enabled.
        Store `core` as self._core for later use.
        """
        self._core = core
        self._enabled = True

    def disable(self) -> None:
        """Called when the plugin is disabled or auto-disabled by security."""
        self._enabled = False
        self._core = None

    # --- Settings ---

    def get_settings_schema(self) -> list[dict]:
        """
        Return a list of field definitions for the settings UI.
        Each field is a dict with keys:
            key (str)       — settings dict key
            label (str)     — display label
            type (str)      — "text", "password", "number", "toggle", "select"
            required (bool) — whether the field is required
            default (any)   — default value
            options (list)  — for type="select", list of {value, label} dicts
            hint (str)      — optional help text shown below the field
        """
        return []

    def configure(self, settings: dict) -> None:
        """
        Apply and persist new settings.
        Called by PluginManager when the user saves settings in the UI.
        """
        pass

    # --- Status ---

    def get_status(self) -> dict:
        """
        Return a status dict for display in the plugin card.
        Keys: ok (bool), message (str, optional)
        """
        return {"ok": self._enabled}
