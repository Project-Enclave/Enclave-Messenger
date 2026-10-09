"""
Imported first by every test: puts src/ on sys.path and points the app at a
throw-away ENCLAVE_HOME so tests never touch real profiles or keys.
(ENCLAVE_HOME works on every OS; overriding HOME does not on Windows.)
"""
import atexit
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

if not os.environ.get("ENCLAVE_HOME"):
    _tmp = tempfile.mkdtemp(prefix="enclave_test_home_")
    os.environ["ENCLAVE_HOME"] = _tmp
    atexit.register(shutil.rmtree, _tmp, ignore_errors=True)
