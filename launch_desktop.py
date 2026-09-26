"""
launch_desktop.py — single-entrypoint launcher for packaged builds
(PyInstaller). Starts the same Flask app web.py serves, but:

  - auto-picks an available port instead of assuming 5000 is free
    (a reviewer's machine may already have something on it)
  - opens the user's default browser automatically, so running the
    executable is a genuine double-click-and-try experience with no
    terminal reading required
  - keeps a console window open with basic status, since Windows users
    running a onefile .exe expect *something* to show it's alive

This is deliberately separate from web.py's own __main__ block (which
still works unchanged for `python web.py` during development) rather
than modifying it, so the normal dev workflow is untouched.
"""

import os
import socket
import sys
import threading
import time
import webbrowser

# When PyInstaller freezes this into a onefile executable, sys._MEIPASS is
# the temp extraction dir bundled resources live in — but user data (chats,
# keys, config) already lives under ~/.enclave-messenger/ regardless (see
# core/profiles.py), so no path adjustment is needed for THAT. This is only
# here in case a future asset needs to be loaded relative to the bundle.
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _find_free_port(preferred: int = 5000) -> int:
    for candidate in [preferred, *range(5001, 5011)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    # last resort: let the OS pick
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    import web  # local import: triggers app_core's profile init on first touch

    port = _find_free_port(int(os.environ.get("ENCLAVE_PORT", 5000)))
    url = f"http://127.0.0.1:{port}"

    def _open_browser_soon():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass  # headless environment, e.g. CI smoke-test — just skip

    threading.Thread(target=_open_browser_soon, daemon=True).start()

    print("=" * 60)
    print("  Enclave Messenger")
    print(f"  Running at {url}")
    print("  Your browser should open automatically.")
    print("  Close this window to stop the app.")
    print("=" * 60)

    web.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
