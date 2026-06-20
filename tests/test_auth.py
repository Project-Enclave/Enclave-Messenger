import pytest

from core.auth import verify_passphrase


class DummyIdentity:
    def __init__(self, has_identity=True, candidate=b"cand", stored=b"stored", raise_on_derive=False):
        self._has = has_identity
        self._candidate = candidate
        self._stored = stored
        self._raise = raise_on_derive

    def has_identity(self):
        return self._has

    def derive_key(self, passphrase):
        if self._raise:
            raise Exception("derive failed")
        return self._candidate

    def derive_key_from_stored(self):
        if self._raise:
            raise Exception("derive failed")
        return self._stored


def test_verify_passphrase_no_identity():
    di = DummyIdentity(has_identity=False)
    with pytest.raises(RuntimeError):
        verify_passphrase(di, "pw")


def test_verify_passphrase_success():
    di = DummyIdentity(has_identity=True, candidate=b"abc", stored=b"abc")
    assert verify_passphrase(di, "pw") is True


def test_verify_passphrase_failure_on_mismatch():
    di = DummyIdentity(has_identity=True, candidate=b"abc", stored=b"def")
    assert verify_passphrase(di, "pw") is False


def test_verify_passphrase_handles_exceptions():
    di = DummyIdentity(has_identity=True, raise_on_derive=True)
    # If derive raises, verify_passphrase should return False (not propagate)
    assert verify_passphrase(di, "pw") is False
