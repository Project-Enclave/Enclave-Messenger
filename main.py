"""
Developer shim: `python main.py ...` from a checkout, no install needed.
The real code lives in src/enclave_messenger/; this just puts src/ on the path
and runs `pe-em cli ...`. (Installed users run `pe-em cli` instead.)
This file is not part of the wheel.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from enclave_messenger.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["cli"] + sys.argv[1:]))
