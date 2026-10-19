"""
desktop.py — `pe-em desktop`: start the web UI on a free port and open the
browser. This is also what the packaged executable runs when double-clicked.

  - auto-picks an available port instead of assuming 5000 is free
  - opens the user's default browser automatically
  - keeps a console window open with basic status
  - binds 127.0.0.1 only (never the LAN)
"""
from __future__ import annotations

import argparse
import os
import socket
import threading
import time
import webbrowser


def _find_free_port(preferred: int = 5000) -> int:
    for candidate in [preferred, *range(preferred + 1, preferred + 11)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:   # let the OS pick
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pe-em desktop",
        description="Start Enclave Messenger and open it in your browser.")
    parser.add_argument("--profile", default=None, help="profile to open (default: the active one)")
    parser.add_argument("--port", type=int, default=None, help="preferred port (default: 5000, or the profile's)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = parser.parse_args(argv)

    from enclave_messenger import paths, web      # first import creates/migrates the data dirs

    if args.profile or os.environ.get("ENCLAVE_PROFILE"):
        web.select_profile(args.profile or os.environ["ENCLAVE_PROFILE"])

    prof = web._profiles.get_profile(web.app_core._active_profile) or {}
    preferred = (args.port or int(os.environ.get("ENCLAVE_PORT", 0)) or prof.get("web_port")
                 or web.app_core.config.get_setting("port", 5000))
    port = _find_free_port(int(preferred))
    url = f"http://127.0.0.1:{port}"

    if not args.no_browser:
        def _open_browser_soon():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass                                # headless (CI smoke test): skip
        threading.Thread(target=_open_browser_soon, daemon=True).start()

    print("=" * 60)
    print("  Enclave Messenger")
    print(f"  Running at {url}")
    print(f"  Your data: {paths.data_dir()}")
    if not args.no_browser:
        print("  Your browser should open automatically.")
    print("  Close this window (or press Ctrl+C) to stop the app.")
    print("=" * 60)

    web._PORT = port
    web.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
