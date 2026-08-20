"""
test_crypto_performance.py — correctness and performance tests for the
CryptoManager v2 key schedule (root key derived once via a fixed
per-identity salt, not re-derived via Scrypt on every message) and the
IdentityManager.crypto_salt persistence it depends on.

Run: python3 test_crypto_performance.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.crypto.crypto_manager import CryptoManager
from core.identity.key_manager import IdentityManager
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PASS, FAIL = [], []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} — {name}")


def test_correctness():
    salt = os.urandom(16)
    cm = CryptoManager("correct-horse-battery-staple", root_salt=salt)

    token = cm.encrypt("hello enclave", chat_id="chat1", created_at="123")
    check("encrypt/decrypt round-trips correctly", cm.decrypt(token) == "hello enclave")

    # Two messages, same manager instance — different random per-message
    # salts must still each decrypt correctly (domain separation preserved
    # even though the expensive root key is now shared/cached).
    t1 = cm.encrypt("message one", chat_id="c", created_at="1")
    t2 = cm.encrypt("message two", chat_id="c", created_at="2")
    check("two messages from the same manager both decrypt correctly",
          cm.decrypt(t1) == "message one" and cm.decrypt(t2) == "message two")
    check("their ciphertext tokens are different (different per-message salts)",
          t1 != t2)

    # Wrong passphrase, same salt — must fail.
    wrong = CryptoManager("wrong-passphrase", root_salt=salt)
    try:
        wrong.decrypt(token)
        check("wrong passphrase is rejected", False)
    except Exception:
        check("wrong passphrase is rejected", True)

    # Same passphrase, DIFFERENT salt — must also fail (proves salt isn't
    # silently ignored / a hardcoded constant).
    other_salt_mgr = CryptoManager("correct-horse-battery-staple", root_salt=os.urandom(16))
    try:
        other_salt_mgr.decrypt(token)
        check("same passphrase but different salt is rejected", False)
    except Exception:
        check("same passphrase but different salt is rejected", True)

    # Tampered ciphertext must fail (AEAD tag check).
    tampered = token[:-4] + "XXXX"
    try:
        cm.decrypt(tampered)
        check("tampered token is rejected", False)
    except Exception:
        check("tampered token is rejected", True)

    # An old v1-schema token must be explicitly rejected with a clear
    # error, not silently mishandled.
    import json, base64
    old_style_envelope = {
        "header": {"v": 1, "alg": "AES-256-GCM", "kdf": "scrypt", "purpose": "message",
                   "chat_id": "c", "created_at": "1", "salt": base64.urlsafe_b64encode(os.urandom(16)).decode(),
                   "nonce": base64.urlsafe_b64encode(os.urandom(12)).decode()},
        "ciphertext": base64.urlsafe_b64encode(b"doesn't matter, should fail on version check").decode(),
    }
    old_token = base64.urlsafe_b64encode(json.dumps(old_style_envelope).encode()).decode()
    try:
        cm.decrypt(old_token)
        check("old v1-schema token is explicitly rejected", False)
    except ValueError as e:
        check("old v1-schema token is explicitly rejected", "v1" in str(e) or "schema" in str(e).lower())

    # Constructor requires root_salt now — this should be a hard error,
    # not a silent fallback to something insecure.
    try:
        CryptoManager("pw", root_salt=None)
        check("CryptoManager requires a non-empty root_salt", False)
    except ValueError:
        check("CryptoManager requires a non-empty root_salt", True)


def test_performance():
    salt = os.urandom(16)
    cm = CryptoManager("some passphrase", root_salt=salt)  # pays Scrypt cost once, here

    N = 30
    tokens = [cm.encrypt(f"message {i}", chat_id="c", created_at=str(i)) for i in range(N)]

    start = time.monotonic()
    for t in tokens:
        cm.decrypt(t)
    elapsed_new = time.monotonic() - start

    # Reference point: what N raw Scrypt derivations (the old per-message
    # cost) actually costs on this machine, using the exact same
    # parameters CryptoManager uses internally.
    start = time.monotonic()
    for i in range(N):
        Scrypt(salt=os.urandom(16), length=32, n=2**14, r=8, p=1).derive(b"some passphrase")
    elapsed_raw_scrypt_reference = time.monotonic() - start

    print(f"  {N} decrypts with the fix: {elapsed_new:.3f}s total "
          f"({elapsed_new/N*1000:.1f}ms/msg)")
    print(f"  {N} raw Scrypt derivations (what the OLD code paid per "
          f"message): {elapsed_raw_scrypt_reference:.3f}s total "
          f"({elapsed_raw_scrypt_reference/N*1000:.1f}ms/msg)")

    check(f"{N} decrypts are dramatically faster than {N} Scrypt derivations would be",
          elapsed_new < elapsed_raw_scrypt_reference / 5)


def test_identity_salt_persistence():
    tmp = tempfile.mkdtemp()

    # Fresh identity: generate, save, and the salt should be persisted.
    im = IdentityManager(storage_dir=os.path.join(tmp, "id1"))
    im.generate_new_identity()
    salt_before = im.crypto_salt
    check("crypto_salt is generated on identity creation", salt_before is not None and len(salt_before) == 16)
    im.save_identity(passphrase="testpass")
    check("crypto_salt.bin was written to disk",
          os.path.exists(os.path.join(tmp, "id1", "crypto_salt.bin")))

    # Load into a FRESH IdentityManager instance — salt must round-trip
    # exactly, or every previously-encrypted message becomes unreadable.
    im2 = IdentityManager(storage_dir=os.path.join(tmp, "id1"))
    im2.load_identity(passphrase="testpass")
    check("crypto_salt survives a save -> fresh-instance -> load round-trip",
          im2.crypto_salt == salt_before)

    mode = oct(os.stat(im2.crypto_salt_file).st_mode)[-3:]
    check(f"crypto_salt.bin is chmod 600 (got {mode})", mode == "600")

    # A message encrypted before "logout" must decrypt correctly after
    # a real save/load cycle using the persisted salt — the actual
    # end-to-end claim.
    cm1 = CryptoManager("testpass", root_salt=im.crypto_salt)
    token = cm1.encrypt("still here after reload", chat_id="c", created_at="1")
    cm2 = CryptoManager("testpass", root_salt=im2.crypto_salt)
    check("message encrypted before reload decrypts correctly after reload",
          cm2.decrypt(token) == "still here after reload")

    # Simulate an identity created BEFORE crypto_salt existed (delete the
    # file, keep the PEM keys) — load_identity() should gracefully
    # generate one rather than crashing.
    os.remove(os.path.join(tmp, "id1", "crypto_salt.bin"))
    im3 = IdentityManager(storage_dir=os.path.join(tmp, "id1"))
    im3.load_identity(passphrase="testpass")
    check("loading an identity with no crypto_salt.bin doesn't crash",
          im3.crypto_salt is not None)
    check("a new crypto_salt.bin gets created for a pre-existing identity",
          os.path.exists(os.path.join(tmp, "id1", "crypto_salt.bin")))

    # delete_identity() should clean up the salt file too.
    im3.delete_identity()
    check("delete_identity() removes crypto_salt.bin too",
          not os.path.exists(os.path.join(tmp, "id1", "crypto_salt.bin")))


def main():
    test_correctness()
    test_performance()
    test_identity_salt_persistence()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
