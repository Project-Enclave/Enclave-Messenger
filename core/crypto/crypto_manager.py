import os
import json
import time
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


ALPHABET = "a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz"
SCHEMA_VERSION = 1


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _derive_shift(chat_id: str, created_at: str) -> int:
    seed = f"{chat_id}:{created_at}".encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return digest[0] % len(ALPHABET)


def _normalize_prekey(prekey: str) -> str:
    cleaned = []
    for ch in prekey.lower():
        if ch in ALPHABET:
            cleaned.append(ch)
    return "".join(cleaned) or "a"


def _vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = _normalize_prekey(key)
    out = []
    key_index = 0
    n = len(ALPHABET)

    for ch in text:
        low = ch.lower()
        if low in ALPHABET:
            t = ALPHABET.index(low)
            k = ALPHABET.index(key[key_index % len(key)])
            idx = (t - k) % n if decrypt else (t + k) % n
            res = ALPHABET[idx]
            out.append(res.upper() if ch.isupper() else res)
            key_index += 1
        else:
            out.append(ch)

    return "".join(out)


def _caesar(text: str, shift: int, decrypt: bool = False) -> str:
    out = []
    n = len(ALPHABET)
    actual_shift = (-shift if decrypt else shift) % n

    for ch in text:
        low = ch.lower()
        if low in ALPHABET:
            idx = (ALPHABET.index(low) + actual_shift) % n
            res = ALPHABET[idx]
            out.append(res.upper() if ch.isupper() else res)
        else:
            out.append(ch)

    return "".join(out)


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

    def _storage_key(self, salt: bytes) -> bytes:
        return self._subkey(salt, b"enclave-storage-key")

    def pre_encrypt(self, plaintext: str, chat_id: str, created_at: str, prekey: str) -> str:
        shift = _derive_shift(chat_id, created_at)
        stage1 = _vigenere(plaintext, prekey, decrypt=False)
        stage2 = _caesar(stage1, shift, decrypt=False)
        return stage2

    def pre_decrypt(self, text: str, chat_id: str, created_at: str, prekey: str) -> str:
        shift = _derive_shift(chat_id, created_at)
        stage1 = _caesar(text, shift, decrypt=True)
        stage2 = _vigenere(stage1, prekey, decrypt=True)
        return stage2

    def encrypt(self, plaintext: str, chat_id: str, created_at: str, prekey: str = "") -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._message_key(salt)

        pre_encrypted = self.pre_encrypt(plaintext, chat_id, created_at, prekey)

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
        ciphertext = aesgcm.encrypt(nonce, pre_encrypted.encode("utf-8"), aad)

        envelope = {
            "header": header,
            "ciphertext": _b64e(ciphertext),
        }

        return _b64e(_canonical_json(envelope))

    def decrypt(self, token: str, prekey: str = "") -> str:
        envelope = json.loads(_b64d(token).decode("utf-8"))

        header = envelope["header"]
        if header["v"] != SCHEMA_VERSION:
            raise ValueError("Unsupported schema version.")

        if header["purpose"] != "message":
            raise ValueError("Invalid envelope purpose.")

        salt = _b64d(header["salt"])
        nonce = _b64d(header["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])

        key = self._message_key(salt)
        aad = _canonical_json(header)

        aesgcm = AESGCM(key)
        pre_encrypted = aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")

        return self.pre_decrypt(
            pre_encrypted,
            chat_id=header["chat_id"],
            created_at=header["created_at"],
            prekey=prekey,
        )

    def encrypt_message(self, message_type: str, body: dict, chat_id: str, prekey: str = "") -> str:
        created_at = str(int(time.time()))
        payload = {
            "type": message_type,
            "chat_id": chat_id,
            "created_at": created_at,
            "body": body,
        }
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return self.encrypt(plaintext, chat_id=chat_id, created_at=created_at, prekey=prekey)

    def decrypt_message(self, token: str, prekey: str = "") -> dict:
        plaintext = self.decrypt(token, prekey=prekey)
        message = json.loads(plaintext)

        required = {"type", "chat_id", "created_at", "body"}
        if not required.issubset(message):
            raise ValueError("Invalid message schema.")

        return message
