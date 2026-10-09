"""
cli.py — the `pe-em` / `enclave-messenger` command.

  pe-em                     open the app in your browser (same as `pe-em desktop`)
  pe-em desktop             start the web UI on a free port and open the browser
  pe-em web [--host lan]    start the web UI (no browser)
  pe-em tui                 terminal UI
  pe-em cli ...             the original command-line interface (init, run, encrypt, ...)
  pe-em setup               first-run wizard: display name, SMS gateway, identity
  pe-em paths               show where config, data and logs live
  pe-em migrate             copy data from the old ~/.enclave-messenger
  pe-em reset               delete this app's data (asks first)
  pe-em --version

Importing this module has NO side effects: nothing is created on disk until a
command that needs data actually runs, so `--help`, `--version` and `paths`
are always safe.
"""
from __future__ import annotations

import json
import sys

from enclave_messenger import __version__

HELP = """\
Project Enclave - Enclave Messenger  (pe-em)

usage: pe-em [command] [options]

commands:
  desktop     start the web UI and open it in your browser  (default)
  web         start the web UI only               (--host lan, --port N, --profile NAME)
  tui         terminal UI                         (--profile NAME)
  cli         original command-line interface     (run, init, encrypt, decrypt, sms, bt ...)
  setup       first-run wizard (display name, SMS gateway, identity)
  paths       show where config, data and logs live
  migrate     copy data from the old ~/.enclave-messenger  (--dry-run, --cleanup-legacy)
  reset       delete this app's data on this computer (asks first)

  -V, --version   show the version        -h, --help   show this help

Use `pe-em <command> --help` for a command's options.
"""


def _fail(msg: str, code: int = 1) -> int:
    print(msg, file=sys.stderr)
    return code


def _guarded(fn):
    """
    Run a command, turning a failed first-launch migration into a clean message.

    `<command> --help` must never touch the user's data: importing the app creates
    the default profile and the first launch migrates an old install. So for help
    the command runs against a throw-away ENCLAVE_HOME that is deleted afterwards.
    """
    def run(rest):
        import os
        from enclave_messenger import paths
        from enclave_messenger.migrate import MigrationError
        if any(a in ("-h", "--help") for a in rest):
            import shutil
            import tempfile
            scratch = tempfile.mkdtemp(prefix="enclave-help-")
            os.environ["ENCLAVE_HOME"] = scratch
            paths.reset_cache()
            try:
                return fn(rest)
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
        try:
            paths.ensure_ready()
        except MigrationError as e:
            return _fail(str(e))
        return fn(rest)
    return run


@_guarded
def _desktop(rest):
    from enclave_messenger import desktop
    return desktop.main(rest)


@_guarded
def _web(rest):
    from enclave_messenger import web
    return web.main(rest)


@_guarded
def _tui(rest):
    from enclave_messenger import tui
    return tui.main(rest)


@_guarded
def _core_cli(rest):
    from enclave_messenger import main as core_main
    return core_main.main(rest)


@_guarded
def _setup(rest):
    from enclave_messenger import setup_wizard
    return setup_wizard.main(rest)


def _paths(rest):
    from enclave_messenger import paths
    d = paths.describe()
    if "--json" in rest:
        print(json.dumps(d, indent=2))
        return 0
    width = max(len(k) for k in d)
    for k, v in d.items():
        print(f"{k:<{width}}  {v}")
    return 0


def _migrate(rest):
    import argparse
    from enclave_messenger import migrate, paths
    ap = argparse.ArgumentParser(prog="pe-em migrate",
        description="Copy data from the old ~/.enclave-messenger to the per-user directories. "
                    "The original is never modified.")
    ap.add_argument("--dry-run", action="store_true", help="show what would be copied; change nothing")
    ap.add_argument("--force", action="store_true", help="copy even if an instance looks like it is running")
    ap.add_argument("--cleanup-legacy", action="store_true",
                    help="delete the OLD copy after a completed migration (asks first)")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    a = ap.parse_args(rest)
    try:
        if a.cleanup_legacy:
            old = paths.legacy_dir()
            if not (paths.data_dir() / migrate.MARKER_NAME).is_file():
                return _fail("No completed migration found; refusing to delete the old data.")
            if not a.yes:
                print(f"This permanently deletes {old}.\nYour data now lives in {paths.data_dir()}.")
                if input("Type DELETE to continue: ").strip() != "DELETE":
                    return _fail("Cancelled.", 1)
            freed = migrate.cleanup_legacy()
            print(f"Removed {old} ({freed} bytes).")
            return 0
        res = migrate.run(dry_run=a.dry_run, force=a.force)
    except migrate.MigrationError as e:
        return _fail(str(e))
    if res.get("dry_run"):
        print(f"Would copy {res['files']} files ({res['bytes']} bytes), profiles: "
              f"{', '.join(res['profiles']) or 'none'}")
        print(f"  from {res['legacy']}\n  to   {res['data']}  (+ registry in {res['config']})")
    elif res.get("already_done"):
        print("Nothing to do: the new location is already set up.")
    else:
        print(f"Done: {res['files_verified']} files copied and verified.")
        for n in res.get("notes", []):
            print("  note:", n)
        print(f"The original at {res['legacy']} is untouched.")
    return 0


def _reset(rest):
    from enclave_messenger import housekeeping
    return housekeeping.main(rest)


COMMANDS = {
    "desktop": _desktop, "web": _web, "tui": _tui, "cli": _core_cli, "setup": _setup,
    "paths": _paths, "migrate": _migrate, "reset": _reset,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return COMMANDS["desktop"]([])
    first, rest = argv[0], argv[1:]
    if first in ("-h", "--help", "help"):
        print(HELP)
        return 0
    if first in ("-V", "--version", "version"):
        from enclave_messenger import paths
        print(f"pe-em {__version__} ({paths.install_kind()}, python {sys.version.split()[0]})")
        return 0
    if first.startswith("-"):                       # `enclave-messenger --profile x`
        return COMMANDS["desktop"](argv)
    handler = COMMANDS.get(first)
    if handler is None:
        return _fail(f"pe-em: unknown command '{first}'\n\n{HELP}", 2)
    return handler(rest) or 0


def run() -> None:
    """Console-script entry point: a closed pipe (`pe-em --help | head`) is not an error."""
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)


if __name__ == "__main__":
    run()
