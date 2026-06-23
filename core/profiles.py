"""
core/profiles.py — Profile registry for Enclave Messenger.

Manages named profiles stored under ~/.enclave-messenger/profiles/<name>/.
Each profile has its own isolated identity, chats, peers, config, and runtime ports.

Registry lives at: ~/.enclave-messenger/registry.json
Profile data at:   ~/.enclave-messenger/profiles/<name>/

Storage layout per profile:
    ~/.enclave-messenger/profiles/<name>/identity/   — Ed25519 + X25519 keys
    ~/.enclave-messenger/profiles/<name>/config/     — ConfigStore
    ~/.enclave-messenger/profiles/<name>/chats/      — ChatStore
    ~/.enclave-messenger/profiles/<name>/peers/      — PeerStore
    ~/.enclave-messenger/profiles/<name>/logs/       — LogStore

Each profile also has its own transport_port and web_port so multiple
instances can run simultaneously on the same device.
"""

import json
import os

ENCLAVE_HOME = os.path.join(os.path.expanduser("~"), ".enclave-messenger")
PROFILES_DIR = os.path.join(ENCLAVE_HOME, "profiles")
REGISTRY_FILE = os.path.join(ENCLAVE_HOME, "registry.json")

_DEFAULT_TRANSPORT_PORT = 43100
_DEFAULT_WEB_PORT = 5000
_PORT_STEP = 10  # each new profile gets ports incremented by this


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_home():
    os.makedirs(PROFILES_DIR, exist_ok=True)
    if not os.path.exists(REGISTRY_FILE):
        _write_registry({"active": None, "profiles": {}})


def _read_registry() -> dict:
    _ensure_home()
    with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_registry(data: dict):
    os.makedirs(ENCLAVE_HOME, exist_ok=True)
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _next_ports(profiles: dict) -> tuple[int, int]:
    """Pick the next unused transport + web port pair."""
    used_transport = {p["transport_port"] for p in profiles.values()}
    used_web = {p["web_port"] for p in profiles.values()}
    t = _DEFAULT_TRANSPORT_PORT
    while t in used_transport:
        t += _PORT_STEP
    w = _DEFAULT_WEB_PORT
    while w in used_web:
        w += _PORT_STEP
    return t, w


def _validate_name(name: str):
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError(
            "Profile name must be alphanumeric (hyphens and underscores allowed)."
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_profiles() -> list[dict]:
    """Return all profiles as a sorted list of dicts."""
    reg = _read_registry()
    active = reg.get("active")
    result = []
    for name, meta in reg["profiles"].items():
        entry = dict(meta)
        entry["name"] = name
        entry["is_active"] = name == active
        result.append(entry)
    return sorted(result, key=lambda p: p["name"])


def get_active_profile() -> str | None:
    """Return the name of the currently active profile, or None."""
    return _read_registry().get("active")


def create_profile(
    name: str,
    username: str = None,
    transport_port: int = None,
    web_port: int = None,
) -> dict:
    """
    Create a new profile and register it.
    Raises ValueError if the name is invalid or already taken.
    Returns the new profile dict.
    """
    _validate_name(name)
    reg = _read_registry()
    if name in reg["profiles"]:
        raise ValueError(f"Profile '{name}' already exists.")

    t_port, w_port = _next_ports(reg["profiles"])
    transport_port = transport_port or t_port
    web_port = web_port or w_port

    profile_dir = os.path.join(PROFILES_DIR, name)
    os.makedirs(profile_dir, exist_ok=True)

    meta = {
        "username": username or name,
        "transport_port": transport_port,
        "web_port": web_port,
        "data_dir": profile_dir,
    }
    reg["profiles"][name] = meta
    if reg["active"] is None:
        reg["active"] = name
    _write_registry(reg)
    return {**meta, "name": name, "is_active": reg["active"] == name}


def delete_profile(name: str) -> bool:
    """
    Remove a profile from the registry.
    Does NOT delete files on disk — identity and chat history are preserved.
    Returns True if deleted, False if not found.
    """
    reg = _read_registry()
    if name not in reg["profiles"]:
        return False
    del reg["profiles"][name]
    if reg.get("active") == name:
        remaining = list(reg["profiles"].keys())
        reg["active"] = remaining[0] if remaining else None
    _write_registry(reg)
    return True


def rename_profile(old_name: str, new_name: str) -> dict:
    """
    Rename a profile. Raises ValueError if old_name not found or new_name taken.
    Note: the data_dir on disk is NOT renamed — only the registry entry changes.
    """
    _validate_name(new_name)
    reg = _read_registry()
    if old_name not in reg["profiles"]:
        raise ValueError(f"Profile '{old_name}' not found.")
    if new_name in reg["profiles"]:
        raise ValueError(f"Profile '{new_name}' already exists.")
    reg["profiles"][new_name] = reg["profiles"].pop(old_name)
    reg["profiles"][new_name]["username"] = new_name
    if reg.get("active") == old_name:
        reg["active"] = new_name
    _write_registry(reg)
    return {**reg["profiles"][new_name], "name": new_name, "is_active": reg["active"] == new_name}


def set_active_profile(name: str) -> dict:
    """
    Mark a profile as the active one for single-instance UI switching.
    Raises ValueError if the profile does not exist.
    """
    reg = _read_registry()
    if name not in reg["profiles"]:
        raise ValueError(f"Profile '{name}' not found.")
    reg["active"] = name
    _write_registry(reg)
    return {**reg["profiles"][name], "name": name, "is_active": True}


def get_profile(name: str) -> dict | None:
    """Return a single profile dict, or None if not found."""
    reg = _read_registry()
    meta = reg["profiles"].get(name)
    if meta is None:
        return None
    return {**meta, "name": name, "is_active": reg.get("active") == name}


def get_profile_data_dir(name: str) -> str:
    """
    Return the data directory for a named profile, creating it if needed.
    Raises ValueError if the profile does not exist in the registry.
    """
    reg = _read_registry()
    meta = reg["profiles"].get(name)
    if meta is None:
        raise ValueError(f"Profile '{name}' not found.")
    path = meta["data_dir"]
    os.makedirs(path, exist_ok=True)
    return path


def ensure_default_profile() -> str:
    """
    Create a 'default' profile if none exist.
    Returns the name of the active profile.
    """
    reg = _read_registry()
    if not reg["profiles"]:
        create_profile(
            "default",
            username="default",
            transport_port=_DEFAULT_TRANSPORT_PORT,
            web_port=_DEFAULT_WEB_PORT,
        )
    return _read_registry().get("active", "default")
