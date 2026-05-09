"""
e2e.py — End-to-end encryption using X25519 ECDH + AES-256-GCM.

How it works
------------
Sender:
  1. Load recipient's X25519 public key from PeerStore.
  2. Perform ECDH: shared_secret = sender_x25519_priv * recipient_x25519_pub
  3. Derive message key: HKDF-SHA256(shared_secret, salt, info="enclave-e2e")
  4. Encrypt with AES-256-GCM; include sender's x25519_pub in the header
     so the recipient can derive the same shared secret.

Recipient (and sender re-reading their own sent messages):
  1. Extract sender_pub from the envelope header.
  2. Perform ECDH: shared_secret = local_x25519_priv * sender_x25519_pub
     (For the *sender* re-reading: derive using their own priv * recipient_pub
      — same scalar math, same result.)
  3. Derive the same message key, decrypt.

The passphrase / CryptoManager is still used for *local storage* (identity
PEM files). It is no longer involved in messages sent over the wire.
"""

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = 1


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"enclave-e2e",
    )
    return hkdf.derive(shared_secret)


def _pub_raw(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class E2EManager:
    """
    Stateless helper — pass the local X25519 private key on construction.
    """

    def __init__(self, local_x25519_priv: X25519PrivateKey):
        self._priv = local_x25519_priv

    # ------------------------------------------------------------------
    # Encrypt (sender side)
    # ------------------------------------------------------------------

    def encrypt(
        self,
        plaintext: str,
        peer_x25519_pub_b64: str,
        chat_id: str,
        created_at: str,
    ) -> str:
        """
        Encrypt *plaintext* for the peer identified by *peer_x25519_pub_b64*
        (base64url-encoded raw X25519 public key bytes from PeerStore).

        Returns a base64url-encoded JSON envelope (same shape as CryptoManager
        so the rest of the codebase stays compatible).
        """
        peer_pub = X25519PublicKey.from_public_bytes(_b64d(peer_x25519_pub_b64))
        shared   = self._priv.exchange(peer_pub)

        salt  = os.urandom(16)
        nonce = os.urandom(12)
        key   = _derive_key(shared, salt)

        header = {
            "v":          SCHEMA_VERSION,
            "alg":        "X25519-AES-256-GCM",
            "purpose":    "message",
            "chat_id":    chat_id,
            "created_at": created_at,
            "salt":       _b64e(salt),
            "nonce":      _b64e(nonce),
            "sender_pub": _b64e(_pub_raw(self._priv)),
        }

        aad        = _canonical_json(header)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)

        envelope = {
            "header":     header,
            "ciphertext": _b64e(ciphertext),
        }
        return _b64e(_canonical_json(envelope))

    # ------------------------------------------------------------------
    # Decrypt (recipient side, or sender re-reading)
    # ------------------------------------------------------------------

    def decrypt(self, token: str) -> str:
        """
        Decrypt a token produced by E2EManager.encrypt().

        The local private key is used with the sender_pub in the header
        to re-derive the shared secret.
        """
        envelope = json.loads(_b64d(token).decode("utf-8"))

        if "header" not in envelope or "ciphertext" not in envelope:
            raise ValueError("Invalid envelope")

        header = envelope["header"]

        if header.get("v") != SCHEMA_VERSION:
            raise ValueError("Unsupported schema version")
        if header.get("alg") != "X25519-AES-256-GCM":
            raise ValueError("Not an E2E envelope (wrong alg)")
        if header.get("purpose") != "message":
            raise ValueError("Invalid envelope purpose")

        sender_pub = X25519PublicKey.from_public_bytes(_b64d(header["sender_pub"]))
        shared     = self._priv.exchange(sender_pub)

        salt       = _b64d(header["salt"])
        nonce      = _b64d(header["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
        key        = _derive_key(shared, salt)
        aad        = _canonical_json(header)

        return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")

    # ------------------------------------------------------------------
    # Convenience: detect whether a token is E2E or legacy passphrase
    # ------------------------------------------------------------------

    @staticmethod
    def is_e2e_token(token: str) -> bool:
        try:
            envelope = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
            return envelope.get("header", {}).get("alg") == "X25519-AES-256-GCM"
        except Exception:
            return False
