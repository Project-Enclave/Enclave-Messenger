"""
paths.py — where Enclave Messenger keeps things on disk (single source of truth).

Per-user locations come from `platformdirs`:

                  Linux                         macOS                                  Windows
  config  ~/.config/enclave-messenger   ~/Library/Application Support/enclave-messenger  %LOCALAPPDATA%\\enclave-messenger
  data    ~/.local/share/enclave-messenger   (same as config)                            (same as config)
  state   ~/.local/state/enclave-messenger   (same as config)                            (same as config)
  logs    <state>/log                   ~/Library/Logs/enclave-messenger               <state>\\Logs

What lives where
  config/registry.json         profile registry (which profiles exist, their ports)
  data/profiles/<name>/        one self-contained folder per profile: encrypted
                               identity keys, chats, peers, that profile's config
  data/plugins/<id>/           user-installed plugins
  state/                       lock + migration bookkeeping
  log/                         log files

Because macOS and Windows put config and data in the SAME folder, nothing in
config/ and data/ shares a name.

`ENCLAVE_HOME=/some/dir` overrides everything: config/, data/ and state/ are
created under it. Tests and developers use this to stay out of real data.

The old location, ~/.enclave-messenger, is only ever READ (by migrate.py).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "enclave-messenger"
LEGACY_DIRNAME = ".enclave-messenger"


def env_home() -> Path | None:
    v = os.environ.get("ENCLAVE_HOME", "").strip()
    return Path(v).expanduser().absolute() if v else None


def _pd():
    import platformdirs
    return platformdirs


def config_dir() -> Path:
    h = env_home()
    return h / "config" if h else Path(_pd().user_config_dir(APP_NAME, appauthor=False))


def data_dir() -> Path:
    h = env_home()
    return h / "data" if h else Path(_pd().user_data_dir(APP_NAME, appauthor=False))


def state_dir() -> Path:
    h = env_home()
    return h / "state" if h else Path(_pd().user_state_dir(APP_NAME, appauthor=False))


def log_dir() -> Path:
    h = env_home()
    return h / "state" / "log" if h else Path(_pd().user_log_dir(APP_NAME, appauthor=False))


def profiles_dir() -> Path:
    return data_dir() / "profiles"


def plugins_dir() -> Path:
    return data_dir() / "plugins"


def registry_file() -> Path:
    return config_dir() / "registry.json"


def default_identity_dir() -> Path:
    """Only for code that builds an IdentityManager without a profile."""
    return data_dir() / "identity"


def legacy_dir() -> Path:
    return Path.home() / LEGACY_DIRNAME


def make_private_dir(path) -> Path:
    """
    Create `path` (and parents). A directory WE create gets mode 0700 on POSIX
    so other local users cannot even list profiles or key files. Directories
    that already exist are left exactly as they are. No effect on Windows.
    """
    path = Path(path)
    if path.is_dir():
        return path
    parent = path.parent
    if not parent.is_dir():
        if _is_app_dir(parent):
            make_private_dir(parent)
        else:
            parent.mkdir(parents=True, exist_ok=True)   # e.g. ~/.config
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    return path


def _is_app_dir(p: Path) -> bool:
    """True for the app's own directories (as opposed to e.g. ~/.config)."""
    try:
        return APP_NAME in p.parts or (env_home() is not None and env_home() in (p, *p.parents))
    except Exception:
        return False


def ensure_ready(announce=None) -> None:
    """
    Make the per-user directories exist and, the first time a pre-1.1 install
    is found at ~/.enclave-messenger, COPY it over (never move, never delete).
    Idempotent and cheap; safe to call from every entry point.
    """
    global _READY
    if _READY:
        return
    if env_home() is None:
        from enclave_messenger import migrate
        migrate.auto(announce=announce)
    for d in (config_dir(), data_dir(), state_dir()):
        make_private_dir(d)
    _READY = True


_READY = False


def reset_cache() -> None:
    """For tests that change ENCLAVE_HOME inside one process."""
    global _READY
    _READY = False


def install_kind() -> str:
    """'frozen' (PyInstaller exe), 'pipx', 'pip' (site-packages) or 'source' (a checkout)."""
    if getattr(sys, "frozen", False):
        return "frozen"
    here = Path(__file__).resolve()
    if "site-packages" in here.parts or "dist-packages" in here.parts:
        # pipx puts each app in <PIPX_HOME>/venvs/<name>; PIPX_HOME can be called anything
        prefix = Path(sys.prefix)
        is_pipx = prefix.parent.name == "venvs" and any("pipx" in part.lower() for part in prefix.parts)
        return "pipx" if is_pipx else "pip"
    return "source"


def describe() -> dict:
    h = env_home()
    return {
        "install": install_kind(),
        "override": str(h) if h else None,
        "config": str(config_dir()),
        "data": str(data_dir()),
        "state": str(state_dir()),
        "logs": str(log_dir()),
        "registry": str(registry_file()),
        "profiles": str(profiles_dir()),
        "plugins": str(plugins_dir()),
        "legacy": str(legacy_dir()),
        "legacy_present": legacy_dir().is_dir(),
    }
