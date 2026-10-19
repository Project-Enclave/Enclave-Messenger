"""
Imported first by every test: puts src/ on sys.path and points the app at a
throw-away ENCLAVE_HOME so tests never touch real profiles or keys.
(ENCLAVE_HOME works on every OS; overriding HOME does not on Windows.)

Also exports TEST_DIR, ROOT (repo root) and SRC for tests that spawn processes or read repo files.
"""
import atexit
import os
import shutil
import sys
import tempfile

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TEST_DIR)          # the repo root (test/ lives directly under it)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Most tests drive the API directly and are not about logging in. test_login.py turns the
# gate back on for itself; spawned servers inherit this variable.
os.environ.setdefault("ENCLAVE_NO_LOGIN", "1")

if not os.environ.get("ENCLAVE_HOME"):
    _tmp = tempfile.mkdtemp(prefix="enclave_test_home_")
    os.environ["ENCLAVE_HOME"] = _tmp
    atexit.register(shutil.rmtree, _tmp, ignore_errors=True)
