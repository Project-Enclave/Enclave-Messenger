"""
housekeeping.py — `pe-em reset`: delete this app's data from this computer.

This is the ONLY code that deletes user data, and it only ever deletes the
app's own directories (paths.py), after listing them and asking the user to
type DELETE. `pip`/`pipx uninstall` never touches your data; this command is
how you remove it on purpose.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from enclave_messenger import paths


def _targets(include_legacy: bool) -> list[Path]:
    out: list[Path] = []
    for p in (paths.data_dir(), paths.config_dir(), paths.state_dir(), paths.log_dir()):
        if p not in out and not any(p == q or q in p.parents for q in out):
            out.append(p)
    if include_legacy:
        out.append(paths.legacy_dir())
    return [p for p in out if p.exists()]


def _safe_to_delete(p: Path) -> bool:
    """Refuse anything that is not clearly the app's own directory."""
    rp = p.resolve()
    if rp in (Path("/"), Path.home().resolve(), Path.home().resolve().parent):
        return False
    if len(rp.parts) < 3:
        return False
    home = paths.env_home()
    if home is not None:
        return home.resolve() in (rp, *rp.parents)
    return paths.APP_NAME in rp.name or rp.name == paths.LEGACY_DIRNAME


def _size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.is_dir() else p.stat().st_size


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pe-em reset",
        description="Delete Enclave Messenger's data on this computer: profiles, encrypted "
                    "identity keys, chat history, settings and logs. This cannot be undone.")
    ap.add_argument("--dry-run", action="store_true", help="list what would be deleted; delete nothing")
    ap.add_argument("--include-legacy", action="store_true",
                    help="also delete the old ~/.enclave-messenger folder")
    ap.add_argument("--yes", action="store_true", help="skip the typed confirmation (for scripts)")
    a = ap.parse_args(argv)

    targets = _targets(a.include_legacy)
    if not targets:
        print("Nothing to delete.")
        return 0

    print("This would permanently delete:")
    for t in targets:
        print(f"  {t}   ({_size(t)} bytes)")
    print("\nThat includes your identity keys. Without a backup there is NO way to recover them.")
    if a.dry_run:
        return 0

    from enclave_messenger import migrate
    reg = paths.registry_file()
    if reg.is_file():
        try:
            import json
            busy = migrate._running_ports(json.loads(reg.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            busy = []
        if busy:
            print(f"\nAn Enclave instance seems to be running (port {busy[0]} is open). Close it first.",
                  file=sys.stderr)
            return 1

    if not a.yes:
        if not sys.stdin.isatty():
            print("Refusing to delete without a terminal. Re-run with --yes if you really mean it.",
                  file=sys.stderr)
            return 1
        if input("\nType DELETE to confirm: ").strip() != "DELETE":
            print("Cancelled; nothing was deleted.")
            return 1

    code = 0
    for t in targets:
        if not _safe_to_delete(t):
            print(f"Refusing to delete {t}: it does not look like an Enclave directory.", file=sys.stderr)
            code = 1
            continue
        try:
            shutil.rmtree(t) if t.is_dir() else t.unlink()
            print(f"Deleted {t}")
        except OSError as e:
            print(f"Could not delete {t}: {e}", file=sys.stderr)
            code = 1
    paths.reset_cache()
    return code
