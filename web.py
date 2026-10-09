"""
Developer shim: `python web.py ...` from a checkout, no install needed.
The real code lives in src/enclave_messenger/; this just puts src/ on the path
and runs `pe-em web ...`. (Installed users run `pe-em web` instead.)
This file is not part of the wheel.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from enclave_messenger.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["web"] + sys.argv[1:]))
