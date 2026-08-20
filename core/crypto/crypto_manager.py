import os
import json
import base64
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


SCHEMA_VERSION = 2  # v2: root key derived once via a fixed per-identity
                     # salt (see below); v1 tokens are no longer readable —
                     # see decrypt()'s version check.


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


class CryptoManager:
    """
    v2 key schedule: Scrypt (the expensive, deliberately slow step) runs
    ONCE per CryptoManager instance, against a FIXED per-identity salt
    (IdentityManager.crypto_salt, generated once and persisted alongside
    the identity keys) — not per message. Each message still gets its own
    unique key, via a cheap HKDF step keyed by a random per-message salt.

    Why this matters concretely: the old scheme re-ran Scrypt(n=2**14) for
    EVERY encrypt/decrypt call, because the OLD scheme's salt was random
    per message and fed directly into Scrypt — reading a chat history of
    a few hundred messages meant a few hundred full Scrypt derivations to
    render one screen. Scrypt's cost is the entire point of using it for
    passphrase stretching, so that's real, deliberate, per-message cost
    that was never supposed to repeat within a session.
    """

    def __init__(self, passphrase: str, root_salt: bytes):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        if not root_salt:
            raise ValueError(
                "root_salt is required — pass identity.crypto_salt. "
                "(A missing/empty salt here was the old per-message-Scrypt "
                "bug's root cause; this is deliberately not optional.)"
            )
        self._root_key = Scrypt(
            salt=root_salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        ).derive(passphrase.encode("utf-8"))

    def _message_key(self, salt: bytes) -> bytes:
        # Cheap — no Scrypt here. self._root_key already paid that cost
        # exactly once, in __init__.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"enclave-message-key:" + salt,
        )
        return hkdf.derive(self._root_key)

    def encrypt(self, plaintext: str, chat_id: str, created_at: str) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._message_key(salt)

        header = {
            "v": SCHEMA_VERSION,
            "alg": "AES-256-GCM",
            "kdf": "scrypt-hkdf",
            "purpose": "message",
            "chat_id": chat_id,
            "created_at": created_at,
            "salt": _b64e(salt),
            "nonce": _b64e(nonce),
        }

        aad = _canonical_json(header)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

        envelope = {
            "header": header,
            "ciphertext": _b64e(ciphertext),
        }

        return _b64e(_canonical_json(envelope))

    def decrypt(self, token: str) -> str:
        envelope = json.loads(_b64d(token).decode("utf-8"))

        if "header" not in envelope or "ciphertext" not in envelope:
            raise ValueError("Invalid envelope")

        header = envelope["header"]

        if header.get("v") == 1:
            raise ValueError(
                "This message uses the old v1 key schedule (Scrypt "
                "re-derived per message) and can't be decrypted by this "
                "version — the root-key derivation changed. This should "
                "only affect messages encrypted before this update."
            )
        if header.get("v") != SCHEMA_VERSION:
            raise ValueError("Unsupported schema version.")

        if header.get("purpose") != "message":
            raise ValueError("Invalid envelope purpose.")

        salt = _b64d(header["salt"])
        nonce = _b64d(header["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])

        key = self._message_key(salt)
        aad = _canonical_json(header)

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")

    def encrypt_message(self, message_type: str, body: dict, chat_id: str, created_at: str) -> str:
        if not isinstance(body, dict):
            raise TypeError("body must be a dict")

        payload = {
            "type": message_type,
            "chat_id": chat_id,
            "created_at": created_at,
            "body": body,
        }

        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return self.encrypt(plaintext, chat_id=chat_id, created_at=created_at)

    def decrypt_message(self, token: str) -> dict:
        plaintext = self.decrypt(token)
        message = json.loads(plaintext)

        required = {"type", "chat_id", "created_at", "body"}
        if not required.issubset(message):
            raise ValueError("Invalid message schema.")

        return message
