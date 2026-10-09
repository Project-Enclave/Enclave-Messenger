"""
spawn.py — start another copy of this app (e.g. a second profile's web UI)
in a way that works from a source checkout, a pip/pipx install, and the
PyInstaller executable.

The old code ran `[sys.executable, <repo>/web.py ...]`, which does not exist
in a wheel and, in the frozen executable, would have launched a second
desktop app instead of a web server.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def base_argv() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]                      # the exe understands subcommands
    return [sys.executable, "-m", "enclave_messenger"]


def child_env(extra: dict | None = None) -> dict:
    env = dict(os.environ)
    if not getattr(sys, "frozen", False):
        # Make `-m enclave_messenger` importable in the child even when we
        # were started from an uninstalled checkout (python web.py).
        pkg_parent = str(Path(__file__).resolve().parent.parent)
        env["PYTHONPATH"] = pkg_parent + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    if extra:
        env.update(extra)
    return env


def popen_detached(args: list[str], extra_env: dict | None = None) -> subprocess.Popen:
    """Run `<this app> <args>` fully detached; it must outlive the caller."""
    kwargs: dict = dict(
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        env=child_env(extra_env),
    )
    if sys.platform == "win32":
        kwargs["creationflags"] = (subprocess.DETACHED_PROCESS
                                   | subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(base_argv() + list(args), **kwargs)


def spawn_web_profile(name: str, web_port: int) -> subprocess.Popen:
    return popen_detached(["web", "--profile", name, "--port", str(web_port)])
