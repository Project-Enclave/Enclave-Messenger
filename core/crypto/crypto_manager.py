import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


SCHEMA_VERSION = 1


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


class CryptoManager:
    def __init__(self, passphrase: str):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        self.passphrase = passphrase.encode("utf-8")

    def _root_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        return kdf.derive(self.passphrase)

    def _subkey(self, salt: bytes, info: bytes) -> bytes:
        root = self._root_key(salt)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(root)

    def _message_key(self, salt: bytes) -> bytes:
        return self._subkey(salt, b"enclave-message-key")

    def encrypt(self, plaintext: str, chat_id: str, created_at: str) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._message_key(salt)

        header = {
            "v": SCHEMA_VERSION,
            "alg": "AES-256-GCM",
            "kdf": "scrypt",
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
