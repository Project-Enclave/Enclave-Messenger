"""
config_store.py — Persistent app config (username, SMS gateway creds, settings).
Stored as JSON at storage/config/config.json
"""

import os
import json

DEFAULTS = {
    "username": None,
    "sms_gateway": {
        "provider": None,
        "api_key": None,
        "sender_id": None,
    },
    "settings": {
        "port": 5000,
        "debug": False,
        "theme": "dark",
    },
    "plugins": {},
    # Self-reported profile info, broadcast to peers via discovery (see
    # core/network/discovery.py) and returned by GET /identity — the
    # same public-material trust level as username already had.
    "profile": {
        "status": "",        # short free-text status ("away", "on call", ...)
        "bio": "",            # short about-text
        "avatar_color": "",   # hex color for a placeholder avatar, e.g. "#4f7cff"
        "accent": "",         # UI accent color override
    },
    # Store-and-forward relay: whether this node agrees to hold queued
    # envelopes on behalf of OTHER peers while they're offline. Opt-in,
    # same reasoning as dht_enabled — see core/network/relay.py.
    "relay": {
        "enabled": False,
        "ttl_hours": 48,
        "max_total_mb": 20,
    },
}


class ConfigStore:
    def __init__(self, base_dir="storage"):
        self.config_dir = os.path.join(base_dir, "config")
        self.config_file = os.path.join(self.config_dir, "config.json")
        os.makedirs(self.config_dir, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        saved = {}
        if os.path.exists(self.config_file):
            with open(self.config_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
        # Every nested section is rebuilt via {**DEFAULTS[...], **saved.get(...)}
        # rather than reused by reference — dict-unpacking always produces a
        # brand-new dict, so no ConfigStore instance (including this "no file
        # yet" case) ever shares a nested dict with DEFAULTS or with any other
        # instance. Previously the no-file branch returned `dict(DEFAULTS)`,
        # a SHALLOW copy: the top-level dict was new, but nested dicts like
        # DEFAULTS["settings"] were the exact same object DEFAULTS itself
        # holds — so set_setting() on one profile silently mutated
        # DEFAULTS["settings"] in place, which every OTHER ConfigStore
        # created afterward (in the same process, before ever writing its
        # own file) would then inherit as if it were their own setting. One
        # profile's dht_port ended up leaking into a second, unrelated
        # profile's "defaults" this way.
        merged = {**DEFAULTS, **saved}
        merged["sms_gateway"] = {**DEFAULTS["sms_gateway"], **saved.get("sms_gateway", {})}
        merged["settings"] = {**DEFAULTS["settings"], **saved.get("settings", {})}
        merged["plugins"] = saved.get("plugins", {})
        merged["profile"] = {**DEFAULTS["profile"], **saved.get("profile", {})}
        merged["relay"] = {**DEFAULTS["relay"], **saved.get("relay", {})}
        return merged

    def save(self):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self.save()

    def get_setting(self, key, default=None):
        return self._data["settings"].get(key, default)

    def set_setting(self, key, value):
        self._data["settings"][key] = value
        self.save()

    def set_profile(self, status: str = None, bio: str = None,
                     avatar_color: str = None, accent: str = None):
        """Only the fields actually passed (non-None) are changed — same
        partial-update convention as PeerStore.upsert()."""
        prof = dict(self._data.get("profile", {}))
        if status is not None:
            prof["status"] = status
        if bio is not None:
            prof["bio"] = bio
        if avatar_color is not None:
            prof["avatar_color"] = avatar_color
        if accent is not None:
            prof["accent"] = accent
        self._data["profile"] = prof
        self.save()

    def set_relay_config(self, enabled: bool = None, ttl_hours: int = None,
                          max_total_mb: int = None):
        rc = dict(self._data.get("relay", {}))
        if enabled is not None:
            rc["enabled"] = bool(enabled)
        if ttl_hours is not None:
            rc["ttl_hours"] = ttl_hours
        if max_total_mb is not None:
            rc["max_total_mb"] = max_total_mb
        self._data["relay"] = rc
        self.save()

    def get_sms_gateway(self) -> dict:
        return self._data["sms_gateway"]

    def set_sms_gateway(self, provider: str, api_key: str, sender_id: str = None):
        self._data["sms_gateway"] = {
            "provider": provider,
            "api_key": api_key,
            "sender_id": sender_id,
        }
        self.save()

    @property
    def username(self) -> str | None:
        return self._data.get("username")

    @username.setter
    def username(self, value: str):
        self._data["username"] = value
        self.save()

    def all(self) -> dict:
        return dict(self._data)
