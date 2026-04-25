# core/crypto.py
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ALPHABET    = "a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz"
ALPHA_LEN   = len(ALPHABET)
ALPHA_INDEX = {c: i for i, c in enumerate(ALPHABET)}
NOISE_PROTOCOL = "Noise_XX_25519_AESGCM_SHA256"

_CK_MSG  = bytes([1])
_CK_NEXT = bytes([2])


def _vigenere_encrypt(text: str, key: str) -> str:
    out, ki, key_len = [], 0, len(key)
    for ch in text:
        lower = ch.lower()
        if lower not in ALPHA_INDEX:
            out.append(ch); continue
        result = ALPHABET[(ALPHA_INDEX[lower] + ALPHA_INDEX[key[ki % key_len].lower()]) % ALPHA_LEN]
        out.append(result.upper() if ch.isupper() else result)
        ki += 1
    return "".join(out)


def _vigenere_decrypt(text: str, key: str) -> str:
    out, ki, key_len = [], 0, len(key)
    for ch in text:
        lower = ch.lower()
        if lower not in ALPHA_INDEX:
            out.append(ch); continue
        result = ALPHABET[(ALPHA_INDEX[lower] - ALPHA_INDEX[key[ki % key_len].lower()]) % ALPHA_LEN]
        out.append(result.upper() if ch.isupper() else result)
        ki += 1
    return "".join(out)


def _caesar_encrypt(text: str, shift: int) -> str:
    out, shift = [], shift % ALPHA_LEN
    for ch in text:
        lower = ch.lower()
        if lower not in ALPHA_INDEX:
            out.append(ch); continue
        result = ALPHABET[(ALPHA_INDEX[lower] + shift) % ALPHA_LEN]
        out.append(result.upper() if ch.isupper() else result)
    return "".join(out)


def _caesar_decrypt(text: str, shift: int) -> str:
    return _caesar_encrypt(text, -shift)


class PreCipher:
    def __init__(self, vigenere_key: str, chat_created_at: int):
        self.key   = vigenere_key
        self.shift = chat_created_at % ALPHA_LEN

    @classmethod
    def from_shared_secret(cls, shared_secret: bytes, chat_created_at: int) -> "PreCipher":
        derived = hashlib.sha256(shared_secret + b"vigenere_key").digest()
        key = "".join(ALPHABET[b % ALPHA_LEN] for b in derived)
        return cls(key, chat_created_at)

    def encrypt(self, plaintext: str) -> str:
        return _caesar_encrypt(_vigenere_encrypt(plaintext, self.key), self.shift)

    def decrypt(self, ciphertext: str) -> str:
        return _vigenere_decrypt(_caesar_decrypt(ciphertext, self.shift), self.key)


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _dh(private_key: X25519PrivateKey, public_key_bytes: bytes) -> bytes:
    return private_key.exchange(X25519PublicKey.from_public_bytes(public_key_bytes))


def _pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _msg_nonce(counter: int) -> bytes:
    return counter.to_bytes(12, "big")


class NoiseHandshake:
    def __init__(self, is_initiator: bool, local_static_priv: X25519PrivateKey, remote_static_pub: bytes):
        self.is_initiator      = is_initiator
        self.local_static_priv = local_static_priv
        self.remote_static_pub = remote_static_pub
        self.local_ephemeral   = X25519PrivateKey.generate()
        self.chaining_key      = hashlib.sha256(NOISE_PROTOCOL.encode()).digest()
        self.h                 = self.chaining_key[:]
        self.shared_secret: Optional[bytes] = None
        self._done = False

    def _mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    def _mix_key(self, dh_output: bytes):
        self.chaining_key = _hkdf(dh_output, self.chaining_key, b"enclave_ck", 32)

    def step1_initiator(self) -> bytes:
        e_pub = _pub_bytes(self.local_ephemeral)
        self._mix_hash(e_pub)
        return e_pub

    def step2_responder(self, msg: bytes) -> bytes:
        remote_e_pub = msg[:32]
        self._mix_hash(remote_e_pub)
        self._mix_key(_dh(self.local_ephemeral, remote_e_pub))
        s_pub = _pub_bytes(self.local_static_priv)
        self._mix_hash(s_pub)
        self._mix_key(_dh(self.local_static_priv, remote_e_pub))
        return _pub_bytes(self.local_ephemeral) + s_pub

    def step3_initiator(self, msg: bytes) -> bytes:
        remote_e_pub, remote_s_pub = msg[:32], msg[32:64]
        self._mix_hash(remote_e_pub)
        self._mix_key(_dh(self.local_ephemeral, remote_e_pub))
        self._mix_hash(remote_s_pub)
        self._mix_key(_dh(self.local_ephemeral, remote_s_pub))
        self._mix_key(_dh(self.local_static_priv, remote_e_pub))
        self.shared_secret = _hkdf(self.chaining_key, self.h, b"enclave_shared", 32)
        self._done = True
        return _pub_bytes(self.local_static_priv)

    def step4_responder_finish(self, msg: bytes):
        remote_s_pub = msg[:32]
        self._mix_hash(remote_s_pub)
        self._mix_key(_dh(self.local_ephemeral, remote_s_pub))
        self.shared_secret = _hkdf(self.chaining_key, self.h, b"enclave_shared", 32)
        self._done = True

    @property
    def complete(self) -> bool:
        return self._done


class RatchetSession:
    MAX_SKIP = 100

    def __init__(self, shared_secret: bytes, is_initiator: bool, remote_ratchet_pub: bytes = None):
        self.root_key = shared_secret
        self.send_chain_key: Optional[bytes] = None
        self.recv_chain_key: Optional[bytes] = None
        self.send_counter   = 0
        self.recv_counter   = 0
        self.ratchet_priv   = X25519PrivateKey.generate()
        self.ratchet_pub    = _pub_bytes(self.ratchet_priv)
        self.remote_ratchet: Optional[bytes] = remote_ratchet_pub
        self._skipped: dict[Tuple[bytes, int], bytes] = {}

        if remote_ratchet_pub:
            if is_initiator:
                self._ratchet_step(remote_ratchet_pub)
        else:
            # bootstrap from shared secret when no DH exchange has happened yet.
            # initiator and responder are mirrored so alice.send == bob.recv
            if is_initiator:
                self.send_chain_key = _hkdf(shared_secret, b"", b"enclave_initiator_send", 32)
                self.recv_chain_key = _hkdf(shared_secret, b"", b"enclave_responder_send", 32)
            else:
                self.send_chain_key = _hkdf(shared_secret, b"", b"enclave_responder_send", 32)
                self.recv_chain_key = _hkdf(shared_secret, b"", b"enclave_initiator_send", 32)

    def _kdf_rk(self, dh_out: bytes) -> Tuple[bytes, bytes]:
        out = _hkdf(dh_out, self.root_key, b"enclave_rk", 64)
        return out[:32], out[32:]

    def _kdf_ck(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        new_ck  = hmac.new(chain_key, _CK_NEXT, "sha256").digest()
        msg_key = hmac.new(chain_key, _CK_MSG,  "sha256").digest()
        return new_ck, msg_key

    def _ratchet_step(self, remote_pub: bytes):
        self.root_key, self.recv_chain_key = self._kdf_rk(_dh(self.ratchet_priv, remote_pub))
        self.ratchet_priv  = X25519PrivateKey.generate()
        self.ratchet_pub   = _pub_bytes(self.ratchet_priv)
        self.root_key, self.send_chain_key = self._kdf_rk(_dh(self.ratchet_priv, remote_pub))
        self.send_counter  = 0
        self.recv_counter  = 0

    def encrypt(self, plaintext_bytes: bytes) -> Tuple[bytes, bytes, int]:
        if not self.send_chain_key:
            raise RuntimeError("session not initialised")
        self.send_chain_key, msg_key = self._kdf_ck(self.send_chain_key)
        ct = AESGCM(msg_key).encrypt(_msg_nonce(self.send_counter), plaintext_bytes, None)
        n  = self.send_counter
        self.send_counter += 1
        return ct, self.ratchet_pub, n

    def decrypt(self, ciphertext: bytes, sender_ratchet_pub: bytes, msg_number: int) -> bytes:
        skip_key = (sender_ratchet_pub, msg_number)
        if skip_key in self._skipped:
            return self._decrypt_with_key(ciphertext, self._skipped.pop(skip_key), msg_number)
        if sender_ratchet_pub != self.remote_ratchet:
            if self.remote_ratchet is not None:
                # only do a real DH ratchet step after the first message exchange
                self._store_skipped_keys(self.remote_ratchet)
                self._ratchet_step(sender_ratchet_pub)
            # first time seeing this peer — just record their pub, use bootstrapped chain
            self.remote_ratchet = sender_ratchet_pub
        while self.recv_counter < msg_number:
            self.recv_chain_key, skipped_key = self._kdf_ck(self.recv_chain_key)
            self._skipped[(sender_ratchet_pub, self.recv_counter)] = skipped_key
            self.recv_counter += 1
            if len(self._skipped) > self.MAX_SKIP:
                raise RuntimeError("too many skipped messages")
        self.recv_chain_key, msg_key = self._kdf_ck(self.recv_chain_key)
        self.recv_counter += 1
        return self._decrypt_with_key(ciphertext, msg_key, msg_number)

    def _decrypt_with_key(self, ciphertext: bytes, msg_key: bytes, n: int) -> bytes:
        return AESGCM(msg_key).decrypt(_msg_nonce(n), ciphertext, None)

    def _store_skipped_keys(self, ratchet_pub: Optional[bytes]):
        if not ratchet_pub or not self.recv_chain_key:
            return
        for _ in range(self.MAX_SKIP):
            self.recv_chain_key, mk = self._kdf_ck(self.recv_chain_key)
            self._skipped[(ratchet_pub, self.recv_counter)] = mk
            self.recv_counter += 1

    def to_dict(self) -> dict:
        return {
            "root_key":       self.root_key.hex(),
            "send_chain_key": self.send_chain_key.hex() if self.send_chain_key else None,
            "recv_chain_key": self.recv_chain_key.hex() if self.recv_chain_key else None,
            "send_counter":   self.send_counter,
            "recv_counter":   self.recv_counter,
            "ratchet_pub":    self.ratchet_pub.hex(),
            "remote_ratchet": self.remote_ratchet.hex() if self.remote_ratchet else None,
        }


class MessageCrypto:
    def __init__(self, pre_cipher: PreCipher, ratchet: RatchetSession):
        self.pre     = pre_cipher
        self.ratchet = ratchet

    def encrypt_message(self, plaintext: str) -> dict:
        obfuscated = self.pre.encrypt(plaintext)
        ct, rp, n  = self.ratchet.encrypt(obfuscated.encode("utf-8"))
        return {"ct": ct.hex(), "ratchet_pub": rp.hex(), "msg_n": n}

    def decrypt_message(self, payload: dict) -> str:
        ct = bytes.fromhex(payload["ct"])
        rp = bytes.fromhex(payload["ratchet_pub"])
        n  = payload["msg_n"]
        return self.pre.decrypt(self.ratchet.decrypt(ct, rp, n).decode("utf-8"))
