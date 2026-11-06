"""
test_key_wrapping.py - identity key files are protected by scrypt, not just
PKCS#8's built-in PBKDF2 (2,048 iterations).

  * new identities write key_wrap.json, and the raw passphrase alone does NOT
    open the .pem files
  * legacy identities (no key_wrap.json) still unlock and are re-wrapped
  * a wrong passphrase leaves the loaded identity untouched
  * an interrupted re-wrap (mixed key files) still unlocks and heals itself
  * backups carry the parameters; v1 (legacy) backups still restore
  * new passphrases shorter than 12 characters are refused

Run:  python3 -m pytest test/test_key_wrapping.py
"""
import _testenv  # noqa: F401
import json
import os
import shutil
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization

from enclave_messenger.core.identity import key_manager as km
from enclave_messenger.core.identity.key_manager import IdentityManager

PW = "correct horse battery"


def _new(d=None):
    im = IdentityManager(storage_dir=d or tempfile.mkdtemp())
    im.generate_new_identity()
    im.save_identity(passphrase=PW)
    return im


def _raw_opens(path, pw=PW):
    with open(path, "rb") as f:
        data = f.read()
    try:
        serialization.load_pem_private_key(data, password=pw.encode())
        return True
    except ValueError:
        return False


def _write_legacy(im):
    """Re-save im's keys the way <= v1.1.0 did: raw passphrase, no key_wrap.json."""
    enc = serialization.BestAvailableEncryption(PW.encode())
    for key, path in ((im.ed25519_priv, im.ed25519_file), (im.x25519_priv, im.x25519_file)):
        with open(path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, enc))
    if os.path.exists(im.key_wrap_file):
        os.remove(im.key_wrap_file)


def test_new_identity_is_scrypt_wrapped():
    im = _new()
    params = json.load(open(im.key_wrap_file))
    assert params["kdf"] == "scrypt" and params["n"] >= 2 ** 17
    assert (os.stat(im.key_wrap_file).st_mode & 0o777) == 0o600
    assert not _raw_opens(im.ed25519_file), "raw passphrase must not open the PEM"
    assert not _raw_opens(im.x25519_file)
    again = IdentityManager(storage_dir=im.storage_dir)
    assert again.verify_passphrase(PW) and again.load_identity(PW)
    assert again.get_user_id() == im.get_user_id()


def test_legacy_identity_unlocks_and_is_rewrapped():
    im = _new()
    uid = im.get_user_id()
    _write_legacy(im)
    assert _raw_opens(im.ed25519_file)
    fresh = IdentityManager(storage_dir=im.storage_dir)
    assert fresh.verify_passphrase(PW)
    assert not os.path.exists(fresh.key_wrap_file), "verify must not write anything"
    assert fresh.load_identity(PW) and fresh.get_user_id() == uid
    assert os.path.exists(fresh.key_wrap_file), "legacy keys are re-wrapped on unlock"
    assert not _raw_opens(fresh.ed25519_file) and not _raw_opens(fresh.x25519_file)
    assert IdentityManager(storage_dir=im.storage_dir).load_identity(PW)


def test_wrong_passphrase_changes_nothing():
    im = _new()
    uid = im.get_user_id()
    assert not im.verify_passphrase("not the passphrase")
    with pytest.raises(ValueError):
        im.load_identity("not the passphrase")
    assert im.get_user_id() == uid


def test_interrupted_rewrap_still_unlocks():
    im = _new()
    uid = im.get_user_id()
    d = im.storage_dir
    # Simulate a crash during re-wrap: x25519 still under the OLD params
    # (now in key_wrap.prev.json), ed25519 already under the NEW ones.
    old_params = open(im.key_wrap_file).read()
    old_x = open(im.x25519_file, "rb").read()
    im.save_identity(passphrase=PW)              # writes new params + new files
    with open(im.key_wrap_prev_file, "w") as f:
        f.write(old_params)
    with open(im.x25519_file, "wb") as f:
        f.write(old_x)
    fresh = IdentityManager(storage_dir=d)
    assert fresh.load_identity(PW) and fresh.get_user_id() == uid
    assert not os.path.exists(fresh.key_wrap_prev_file), "re-wrap finished and cleaned up"
    assert IdentityManager(storage_dir=d).load_identity(PW)


def test_tampered_params_are_rejected():
    for bad in ({"v": 1, "kdf": "scrypt", "n": 2, "r": 8, "p": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA=="},
                {"v": 1, "kdf": "scrypt", "n": 2 ** 30, "r": 8, "p": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA=="},
                {"v": 1, "kdf": "pbkdf2", "n": 2 ** 17, "r": 8, "p": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA=="}):
        with pytest.raises(ValueError):
            km.validate_key_wrap_params(bad)


def test_backup_round_trip_and_legacy_backup():
    import enclave_messenger.main as app_core
    orig = app_core.identity
    try:
        a = _new()
        app_core.identity = a
        bundle = app_core.export_identity_backup()
        assert bundle["enclave_identity_backup"] == 2 and "key_wrap" in bundle

        b = IdentityManager(storage_dir=tempfile.mkdtemp())
        app_core.identity = b
        assert app_core.restore_identity_backup(bundle, PW)["node_id"] == a.get_user_id()
        assert os.path.exists(b.key_wrap_file)

        # A v1 backup made by <= v1.1.0 (raw-passphrase PEMs, no key_wrap)
        legacy = _new()
        _write_legacy(legacy)
        app_core.identity = legacy
        v1 = app_core.export_identity_backup()
        v1["enclave_identity_backup"] = 1
        v1.pop("key_wrap", None)
        c = IdentityManager(storage_dir=tempfile.mkdtemp())
        app_core.identity = c
        assert app_core.restore_identity_backup(v1, PW)["node_id"] == legacy.get_user_id()
        assert os.path.exists(c.key_wrap_file), "restored legacy keys get re-wrapped"
    finally:
        app_core.identity = orig


def test_short_new_passphrase_refused():
    assert km.passphrase_too_short("short pass")
    assert km.passphrase_too_short("a" * 11)
    assert not km.passphrase_too_short("a" * 12)
    assert "12" in km.MIN_LENGTH_HINT
