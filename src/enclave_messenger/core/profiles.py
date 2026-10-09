"""
core/profiles.py — Profile registry for Enclave Messenger.

Manages named profiles. Locations come from enclave_messenger.paths (per-user
platform directories, or $ENCLAVE_HOME); see that module for the per-OS table.

Registry:     <config dir>/registry.json
Profile data: <data dir>/profiles/<dir>/
Logs:         <log dir>/            (no longer inside the profile folder)

Storage layout per profile:
    <profile>/identity/   — Ed25519 + X25519 keys (passphrase-encrypted)
    <profile>/config/     — ConfigStore
    <profile>/chats/      — ChatStore
    <profile>/peers/      — PeerStore

A profile's `data_dir` is stored RELATIVE ("profiles/<dir>") so the data
folder can be moved or backed up without breaking the registry. Absolute
values written by older versions are still honoured.

Each profile also has its own transport_port and web_port so multiple
instances can run simultaneously on the same device.
"""

import json
import os

from enclave_messenger import paths


def __getattr__(name):
    # Back-compat for code that read the old module-level constants. They are
    # computed on access so ENCLAVE_HOME is always honoured.
    if name == "ENCLAVE_HOME":
        return str(paths.data_dir())
    if name == "PROFILES_DIR":
        return str(paths.profiles_dir())
    if name == "REGISTRY_FILE":
        return str(paths.registry_file())
    raise AttributeError(name)

_DEFAULT_TRANSPORT_PORT = 43100
_DEFAULT_WEB_PORT = 5000
_PORT_STEP = 10  # each new profile gets ports incremented by this


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_home():
    paths.ensure_ready()                     # creates dirs; copies a pre-1.1 install once
    paths.make_private_dir(paths.profiles_dir())
    if not paths.registry_file().exists():
        _write_registry({"active": None, "profiles": {}})


def _resolve_dir(value: str) -> str:
    """Turn a registry data_dir into an absolute path. Relative values must
    stay inside the data directory."""
    if os.path.isabs(value):
        return value                          # written by an older version
    root = os.path.realpath(paths.data_dir())
    full = os.path.realpath(os.path.join(root, value))
    if os.path.commonpath([root, full]) != root:
        raise ValueError(f"profile data_dir {value!r} points outside the data directory")
    return full


def _public(meta: dict) -> dict:
    """What callers see: data_dir is always absolute."""
    out = dict(meta)
    if out.get("data_dir"):
        out["data_dir"] = _resolve_dir(out["data_dir"])
    return out


def _read_registry() -> dict:
    _ensure_home()
    with open(paths.registry_file(), "r", encoding="utf-8") as f:
        return json.load(f)


def _write_registry(data: dict):
    paths.make_private_dir(paths.config_dir())
    target = paths.registry_file()
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, target)                   # never leave a half-written registry


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
        entry = _public(meta)
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

    profile_dir = os.path.join(str(paths.profiles_dir()), name)
    paths.make_private_dir(profile_dir)

    meta = {
        "username": username or name,
        "transport_port": transport_port,
        "web_port": web_port,
        "data_dir": f"profiles/{name}",
    }
    reg["profiles"][name] = meta
    if reg["active"] is None:
        reg["active"] = name
    _write_registry(reg)
    return {**_public(meta), "name": name, "is_active": reg["active"] == name}


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
    return {**_public(reg["profiles"][new_name]), "name": new_name, "is_active": reg["active"] == new_name}


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
    return {**_public(reg["profiles"][name]), "name": name, "is_active": True}


def get_profile(name: str) -> dict | None:
    """Return a single profile dict, or None if not found."""
    reg = _read_registry()
    meta = reg["profiles"].get(name)
    if meta is None:
        return None
    return {**_public(meta), "name": name, "is_active": reg.get("active") == name}


def get_profile_data_dir(name: str) -> str:
    """
    Return the data directory for a named profile, creating it if needed.
    Raises ValueError if the profile does not exist in the registry.
    """
    reg = _read_registry()
    meta = reg["profiles"].get(name)
    if meta is None:
        raise ValueError(f"Profile '{name}' not found.")
    path = _resolve_dir(meta["data_dir"])
    paths.make_private_dir(path)
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
