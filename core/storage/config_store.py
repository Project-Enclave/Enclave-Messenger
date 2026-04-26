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
}


class ConfigStore:
    def __init__(self, base_dir="storage"):
        self.config_dir = os.path.join(base_dir, "config")
        self.config_file = os.path.join(self.config_dir, "config.json")
        os.makedirs(self.config_dir, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.config_file):
            with open(self.config_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            merged = {**DEFAULTS, **saved}
            merged["sms_gateway"] = {**DEFAULTS["sms_gateway"], **saved.get("sms_gateway", {})}
            merged["settings"] = {**DEFAULTS["settings"], **saved.get("settings", {})}
            return merged
        return dict(DEFAULTS)

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
