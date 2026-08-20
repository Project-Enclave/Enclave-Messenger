import os
import base64
import getpass
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization


class IdentityManager:
    def __init__(self, storage_dir="~/.enclave-messenger/identity"):
        self.storage_dir = os.path.expanduser(storage_dir)
        self.ed25519_file = os.path.join(self.storage_dir, "ed25519.pem")
        self.x25519_file = os.path.join(self.storage_dir, "x25519.pem")
        self.crypto_salt_file = os.path.join(self.storage_dir, "crypto_salt.bin")
        self.ed25519_priv = None
        self.x25519_priv = None
        self.crypto_salt = None  # fixed per-identity salt for CryptoManager's root key
        os.makedirs(self.storage_dir, exist_ok=True)

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

        password = passphrase.encode("utf-8")
        encryption = serialization.BestAvailableEncryption(password)

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

        with open(self.ed25519_file, "wb") as f:
            f.write(ed_bytes)
        with open(self.x25519_file, "wb") as f:
            f.write(x_bytes)

        if self.crypto_salt is None:
            self.crypto_salt = os.urandom(16)
        with open(self.crypto_salt_file, "wb") as f:
            f.write(self.crypto_salt)

        # Private keys should never be readable by other local users/groups.
        try:
            os.chmod(self.ed25519_file, 0o600)
            os.chmod(self.x25519_file, 0o600)
            os.chmod(self.crypto_salt_file, 0o600)
        except OSError:
            pass  # best-effort — not all filesystems support it (e.g. some FAT mounts)

        return True

    def load_identity(self, passphrase: str | None = None):
        if not os.path.exists(self.ed25519_file) or not os.path.exists(self.x25519_file):
            return False

        if passphrase is None:
            passphrase = getpass.getpass("Enclave passphrase: ")

        password = passphrase.encode("utf-8")

        with open(self.ed25519_file, "rb") as f:
            self.ed25519_priv = serialization.load_pem_private_key(
                f.read(),
                password=password,
            )

        with open(self.x25519_file, "rb") as f:
            self.x25519_priv = serialization.load_pem_private_key(
                f.read(),
                password=password,
            )

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

        return True

    def has_identity(self):
        return os.path.exists(self.ed25519_file) and os.path.exists(self.x25519_file)

    def delete_identity(self):
        ok = True
        for path in (self.ed25519_file, self.x25519_file, self.crypto_salt_file):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                ok = False
        self.ed25519_priv = None
        self.x25519_priv = None
        self.crypto_salt = None
        return ok
