"""
e2e.py — End-to-end encryption using X25519 ECDH + AES-256-GCM
         with ephemeral sender keys for forward secrecy.

How it works
------------
Sender:
  1. Generate a THROWAWAY ephemeral X25519 key pair (never stored).
  2. Load recipient's static X25519 public key from PeerStore.
  3. ECDH: shared_secret = ephemeral_priv × recipient_identity_pub
  4. Derive message key: HKDF-SHA256(shared_secret, salt, info="enclave-e2e")
  5. Encrypt with AES-256-GCM; include ephemeral_pub in the header.
  6. ephemeral_priv goes out of scope and is destroyed.

Recipient decrypting:
  shared_secret = recipient_identity_priv × ephemeral_pub  (from header)
  → same scalar multiplication, same shared_secret.

Forward secrecy guarantee:
  ephemeral_priv is never stored. Even if the recipient's identity key
  leaks later, past messages cannot be decrypted without ephemeral_priv.

Sender re-reading sent messages:
  NOT possible by re-deriving — ephemeral_priv is gone by design.
  Store the plaintext locally after sending instead.

The identity X25519 key (from IdentityManager) is only used for
receiving (recipient side). It is NOT used to encrypt outgoing messages.
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

SCHEMA_VERSION = 2


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


def _pub_bytes_raw(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class E2EManager:
    """
    Stateless helper — pass the local X25519 identity private key on
    construction. Used ONLY for decrypting incoming messages.
    Outgoing messages use a fresh ephemeral key every time.
    """

    def __init__(self, local_x25519_priv: X25519PrivateKey):
        self._priv = local_x25519_priv

    # ------------------------------------------------------------------
    # Encrypt (sender side) — ephemeral key, forward secrecy
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

        A fresh ephemeral X25519 key pair is generated per call and is
        never stored — forward secrecy is guaranteed.

        Returns a base64url-encoded JSON envelope.

        NOTE: The sender cannot re-decrypt this message later.
              Store the plaintext locally after calling this method.
        """
        # Generate throwaway ephemeral key pair
        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub_raw = _pub_bytes_raw(ephemeral_priv)

        peer_pub = X25519PublicKey.from_public_bytes(_b64d(peer_x25519_pub_b64))
        shared = ephemeral_priv.exchange(peer_pub)
        # ephemeral_priv is no longer referenced after this point

        salt  = os.urandom(16)
        nonce = os.urandom(12)
        key   = _derive_key(shared, salt)

        header = {
            "v":           SCHEMA_VERSION,
            "alg":         "X25519-AES-256-GCM",
            "purpose":     "message",
            "chat_id":     chat_id,
            "created_at":  created_at,
            "salt":        _b64e(salt),
            "nonce":       _b64e(nonce),
            "ephemeral_pub": _b64e(ephemeral_pub_raw),  # throwaway, not identity
        }

        aad        = _canonical_json(header)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)

        envelope = {
            "header":     header,
            "ciphertext": _b64e(ciphertext),
        }
        return _b64e(_canonical_json(envelope))

    # ------------------------------------------------------------------
    # Decrypt (recipient side only)
    # ------------------------------------------------------------------

    def decrypt(self, token: str) -> str:
        """
        Decrypt a token produced by E2EManager.encrypt().

        The shared secret is recovered as:
            local_identity_priv × ephemeral_pub  (ephemeral_pub is in header)

        The sender cannot decrypt their own messages — ephemeral_priv is gone.
        """
        envelope = json.loads(_b64d(token).decode("utf-8"))

        if "header" not in envelope or "ciphertext" not in envelope:
            raise ValueError("Invalid envelope")

        header = envelope["header"]

        if header.get("v") != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: {header.get('v')} "
                f"(expected {SCHEMA_VERSION})"
            )
        if header.get("alg") != "X25519-AES-256-GCM":
            raise ValueError("Not an E2E envelope (wrong alg)")
        if header.get("purpose") != "message":
            raise ValueError("Invalid envelope purpose")

        if "ephemeral_pub" not in header:
            raise ValueError("Missing ephemeral_pub in header")

        ephemeral_pub = X25519PublicKey.from_public_bytes(
            _b64d(header["ephemeral_pub"])
        )

        shared     = self._priv.exchange(ephemeral_pub)
        salt       = _b64d(header["salt"])
        nonce      = _b64d(header["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
        key        = _derive_key(shared, salt)
        aad        = _canonical_json(header)

        return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")

    # ------------------------------------------------------------------
    # Token detection helper
    # ------------------------------------------------------------------

    @staticmethod
    def is_e2e_token(token: str) -> bool:
        try:
            envelope = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
            return envelope.get("header", {}).get("alg") == "X25519-AES-256-GCM"
        except Exception:
            return False
