"""
Entry point for the packaged executable (PyInstaller) and for `python launch_desktop.py`.

Behaves exactly like the `pe-em` command: with no arguments it opens the app in
your browser; `enclave-messenger web --profile NAME` etc. also work, which is
how the app starts additional profiles from inside the executable.

The real code lives in src/enclave_messenger/. This file is not part of the wheel.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from enclave_messenger.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
