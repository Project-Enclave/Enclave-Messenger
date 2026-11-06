import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization


# How the passphrase protects the key files.
#
# The .pem files are standard encrypted PKCS#8, but cryptography's
# BestAvailableEncryption wraps them with PBKDF2-HMAC-SHA256 at only 2,048
# iterations. Anyone who copies the identity folder could guess passphrases
# offline very fast. cryptography can't raise that count for PKCS#8, so the
# passphrase is stretched with scrypt FIRST and the PEM is encrypted under the
# result. An attacker now pays a full scrypt (about 128 MiB of memory) per
# guess, and the files stay ordinary PEMs.
#
# The parameters live in key_wrap.json next to the keys. When that file is
# missing, the identity predates this change: the passphrase is used directly
# (legacy), and load_identity() re-wraps the keys on the first successful
# unlock.
KEY_WRAP_VERSION = 1
KEY_WRAP_DEFAULTS = {"kdf": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}
_KEY_WRAP_LIMITS = {"n": (2 ** 14, 2 ** 20), "r": (1, 16), "p": (1, 4)}


MIN_PASSPHRASE_LEN = 12


# Shown when a new passphrase is too short. A constant, never built from
# the input, and deliberately not named after it (CodeQL treats names like
# *PASSPHRASE* as secrets and flags printing them).
MIN_LENGTH_HINT = (f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters "
                          "(a few random words works well)")


def passphrase_too_short(passphrase: str) -> bool:
    """True if a NEW passphrase is below the minimum. Only applied when an
    identity is created, never to unlocking an existing one."""
    return len(passphrase or "") < MIN_PASSPHRASE_LEN


def new_key_wrap_params() -> dict:
    return {"v": KEY_WRAP_VERSION, **KEY_WRAP_DEFAULTS,
            "salt": base64.b64encode(os.urandom(16)).decode("ascii")}


def validate_key_wrap_params(params) -> dict:
    """Reject anything that isn't a sane scrypt setting (e.g. from a backup)."""
    if not isinstance(params, dict) or params.get("v") != KEY_WRAP_VERSION \
            or params.get("kdf") != "scrypt":
        raise ValueError("unsupported key wrapping parameters")
    for k, (lo, hi) in _KEY_WRAP_LIMITS.items():
        v = params.get(k)
        if not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"key wrapping parameter {k} out of range")
    if params["n"] & (params["n"] - 1):
        raise ValueError("key wrapping parameter n must be a power of two")
    salt = base64.b64decode(params.get("salt", ""), validate=True)
    if not 16 <= len(salt) <= 64:
        raise ValueError("key wrapping salt has a bad length")
    return params


def pem_password(passphrase: str, params: dict | None) -> bytes:
    """The password actually used on the PEM files."""
    if params is None:
        return passphrase.encode("utf-8")          # legacy identities
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    params = validate_key_wrap_params(params)
    key = Scrypt(salt=base64.b64decode(params["salt"]), length=32,
                 n=params["n"], r=params["r"], p=params["p"]).derive(passphrase.encode("utf-8"))
    return key.hex().encode("ascii")


class IdentityManager:
    def __init__(self, storage_dir=None):
        # Callers normally pass the profile's identity folder. The fallback is
        # the per-user data dir (never the old ~/.enclave-messenger).
        if storage_dir is None:
            from enclave_messenger import paths
            storage_dir = str(paths.default_identity_dir())
        self.storage_dir = os.path.expanduser(storage_dir)
        self.ed25519_file = os.path.join(self.storage_dir, "ed25519.pem")
        self.x25519_file = os.path.join(self.storage_dir, "x25519.pem")
        self.crypto_salt_file = os.path.join(self.storage_dir, "crypto_salt.bin")
        self.key_wrap_file = os.path.join(self.storage_dir, "key_wrap.json")
        self.key_wrap_prev_file = os.path.join(self.storage_dir, "key_wrap.prev.json")
        self.ed25519_priv = None
        self.x25519_priv = None
        self.crypto_salt = None  # fixed per-identity salt for CryptoManager's root key
        from enclave_messenger import paths as _paths
        _paths.make_private_dir(self.storage_dir)

    def generate_new_identity(self):
        self.ed25519_priv = ed25519.Ed25519PrivateKey.generate()
        self.x25519_priv = x25519.X25519PrivateKey.generate()
        self.crypto_salt = os.urandom(16)
        return self.get_user_id()

    def get_user_id(self):
        if not self.ed25519_priv:
            raise ValueError("Identity not loaded or generated.")

        pub_bytes = self.ed25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.urlsafe_b64encode(pub_bytes).decode("utf-8").rstrip("=")

    def save_identity(self, passphrase: str | None = None):
        if not self.ed25519_priv or not self.x25519_priv:
            return False

        if passphrase is None:
            passphrase = getpass.getpass("Enclave passphrase: ")

        params = new_key_wrap_params()
        encryption = serialization.BestAvailableEncryption(pem_password(passphrase, params))

        ed_bytes = self.ed25519_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        x_bytes = self.x25519_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        if self.crypto_salt is None:
            self.crypto_salt = os.urandom(16)

        # Write everything to temp files first, then swap them in.
        # Order matters: the new parameters go in BEFORE the key files they
        # protect, and the old ones stay in key_wrap.prev.json until every
        # key file is swapped. At any crash point each key file opens with
        # either the current, the previous, or (legacy) no parameters.
        files = [
            (self.key_wrap_file, json.dumps(params).encode("utf-8")),
            (self.ed25519_file, ed_bytes),
            (self.x25519_file, x_bytes),
            (self.crypto_salt_file, self.crypto_salt),
        ]
        for path, data in files:
            fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        # Keep the previous parameters until the swap is done: if we crash
        # half way, load_identity() can still open whichever key file was
        # written with them.
        if os.path.exists(self.key_wrap_file):
            os.replace(self.key_wrap_file, self.key_wrap_prev_file)
        for path, _ in files:
            os.replace(path + ".tmp", path)
        try:
            os.remove(self.key_wrap_prev_file)
        except OSError:
            pass

        # Private keys should never be readable by other local users/groups.
        for path, _ in files:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # best-effort — not all filesystems support it (e.g. some FAT mounts)

        return True

    def key_wrap_params(self) -> dict | None:
        """The stored scrypt parameters, or None for a legacy identity."""
        return self._read_params(self.key_wrap_file)

    @staticmethod
    def _read_params(path):
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return validate_key_wrap_params(json.load(f))
        except (ValueError, OSError):
            return None

    def _candidate_passwords(self, passphrase: str):
        """PEM passwords to try, best first: current scrypt parameters, the
        previous ones (only present if a re-wrap was interrupted), then the
        raw passphrase (legacy). Yields (password, is_current)."""
        current = self._read_params(self.key_wrap_file)
        if current is not None:
            yield pem_password(passphrase, current), True
        prev = self._read_params(self.key_wrap_prev_file)
        if prev is not None:
            yield pem_password(passphrase, prev), False
        yield pem_password(passphrase, None), current is None and prev is None

    def _open_keys(self, passphrase: str):
        """Return (ed25519_priv, x25519_priv, needs_rewrap) or raise ValueError."""
        with open(self.ed25519_file, "rb") as f:
            ed_pem = f.read()
        with open(self.x25519_file, "rb") as f:
            x_pem = f.read()
        keys, rewrap = [], False
        candidates = list(self._candidate_passwords(passphrase))
        for pem in (ed_pem, x_pem):
            for pw, is_current in candidates:
                try:
                    keys.append(serialization.load_pem_private_key(pem, password=pw))
                    if not is_current or self.key_wrap_params() is None:
                        rewrap = True
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError("Bad decrypt. Incorrect password?")
        return keys[0], keys[1], rewrap

    def verify_passphrase(self, passphrase: str) -> bool:
        """
        True if `passphrase` opens the stored keys. Unlike load_identity() this
        changes nothing in memory or on disk, so it is safe to call while the
        identity is in use (e.g. to check a login attempt).
        """
        if not passphrase or not self.has_identity():
            return False
        try:
            self._open_keys(passphrase)
            return True
        except Exception:
            return False

    def load_identity(self, passphrase: str | None = None):
        if not os.path.exists(self.ed25519_file) or not os.path.exists(self.x25519_file):
            return False

        if passphrase is None:
            passphrase = getpass.getpass("Enclave passphrase: ")

        # Raises ValueError on a wrong passphrase, before touching memory.
        ed, x, needs_rewrap = self._open_keys(passphrase)
        self.ed25519_priv, self.x25519_priv = ed, x

        if os.path.exists(self.crypto_salt_file):
            with open(self.crypto_salt_file, "rb") as f:
                self.crypto_salt = f.read()
        else:
            # Identity created before crypto_salt existed — generate and
            # persist one now rather than leaving CryptoManager unusable.
            # Any message previously encrypted via the old per-message-salt
            # scrypt scheme (schema v1) already can't be read by the new
            # code regardless (see crypto_manager.py's version check), so
            # this doesn't lose anything additional.
            self.crypto_salt = os.urandom(16)
            with open(self.crypto_salt_file, "wb") as f:
                f.write(self.crypto_salt)
            try:
                os.chmod(self.crypto_salt_file, 0o600)
            except OSError:
                pass

        if needs_rewrap:
            # Legacy identity (or an interrupted re-wrap): wrap with fresh
            # scrypt parameters now that we know the passphrase. Failure is
            # not fatal; it is retried on the next unlock.
            try:
                self.save_identity(passphrase=passphrase)
            except OSError:
                pass

        return True

    def has_identity(self):
        return os.path.exists(self.ed25519_file) and os.path.exists(self.x25519_file)

    def delete_identity(self):
        ok = True
        for path in (self.ed25519_file, self.x25519_file, self.crypto_salt_file,
                     self.key_wrap_file):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                ok = False
        self.ed25519_priv = None
        self.x25519_priv = None
        self.crypto_salt = None
        return ok
