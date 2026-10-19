"""Signed end-to-end envelopes for SMS exchanged by Enclave identities.

The SMS Gateway and carrier only see the opaque envelope. Pairing codes bind
an Enclave node ID (Ed25519) to its X25519 encryption key and are signed by
the node identity key.
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from enclave_messenger.core.crypto.e2e import E2EManager


SMS_E2E_PREFIX = "ENCLAVE-SMS/1:"
PAIRING_VERSION = 1
MESSAGE_VERSION = 1


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("invalid encoded key or signature")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as e:
        raise ValueError("invalid encoded key or signature") from e


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _raw_public(key) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def create_pairing_code(identity, username: str = "") -> str:
    if identity.ed25519_priv is None or identity.x25519_priv is None:
        raise RuntimeError("unlock your Enclave identity before creating a pairing code")
    payload = {
        "version": PAIRING_VERSION,
        "node_id": identity.get_user_id(),
        "username": (username or "")[:80],
        "x25519_pub": _b64e(_raw_public(identity.x25519_priv.public_key())),
    }
    payload["signature"] = _b64e(identity.ed25519_priv.sign(_canonical(payload)))
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def verify_pairing_code(code: str) -> dict:
    if not isinstance(code, str) or len(code) > 4096:
        raise ValueError("pairing code is missing or too long")
    try:
        payload = json.loads(code, object_pairs_hook=_no_duplicate_keys)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        raise ValueError("pairing code must be the JSON copied from Enclave settings") from e
    if (not isinstance(payload, dict)
            or set(payload) != {"version", "node_id", "username", "x25519_pub", "signature"}
            or type(payload.get("version")) is not int
            or payload.get("version") != PAIRING_VERSION):
        raise ValueError("unsupported Enclave pairing code")

    node_id = payload.get("node_id")
    x_pub = payload.get("x25519_pub")
    signature = payload.get("signature")
    username = payload.get("username", "")
    if not isinstance(node_id, str) or not isinstance(x_pub, str) or not isinstance(signature, str):
        raise ValueError("pairing code is missing identity keys")
    if not isinstance(username, str) or len(username) > 80:
        raise ValueError("pairing code has an invalid display name")

    ed_raw = _b64d(node_id)
    x_raw = _b64d(x_pub)
    sig_raw = _b64d(signature)
    if len(ed_raw) != 32 or len(x_raw) != 32 or len(sig_raw) != 64:
        raise ValueError("pairing code contains an invalid key")
    if (_b64e(ed_raw) != node_id or _b64e(x_raw) != x_pub
            or _b64e(sig_raw) != signature):
        raise ValueError("pairing code contains a non-canonical key or signature")

    signed = {k: payload[k] for k in ("version", "node_id", "username", "x25519_pub")}
    try:
        Ed25519PublicKey.from_public_bytes(ed_raw).verify(sig_raw, _canonical(signed))
        x_public = X25519PublicKey.from_public_bytes(x_raw)
        # Reject invalid low-order public keys at pairing time, not on send.
        X25519PrivateKey.generate().exchange(x_public)
    except (InvalidSignature, ValueError) as e:
        raise ValueError("pairing code signature or encryption key is invalid") from e

    return {
        "peer_id": node_id,
        "username": username,
        "ed25519_pub": _b64e(ed_raw),
        "x25519_pub": _b64e(x_raw),
    }


def encrypt_sms(plaintext: str, identity, recipient: dict, timestamp: str) -> str:
    if identity.ed25519_priv is None or identity.x25519_priv is None:
        raise RuntimeError("unlock your Enclave identity before sending encrypted SMS")
    # E2EManager's base64 decoder expects the padded form used by PeerStore,
    # while pairing codes use the unpadded form used for node IDs.
    peer_x25519_pub = base64.urlsafe_b64encode(
        _b64d(recipient["x25519_pub"])
    ).decode("ascii")
    token = E2EManager(identity.x25519_priv).encrypt(
        plaintext=plaintext,
        peer_x25519_pub_b64=peer_x25519_pub,
        chat_id=recipient["peer_id"],
        created_at=timestamp,
    )
    payload = {
        "version": MESSAGE_VERSION,
        "from": identity.get_user_id(),
        "to": recipient["peer_id"],
        "timestamp": timestamp,
        "token": token,
    }
    payload["signature"] = _b64e(identity.ed25519_priv.sign(_canonical(payload)))
    return SMS_E2E_PREFIX + json.dumps(payload, separators=(",", ":"), sort_keys=True)


def decrypt_sms(message: str, identity, expected_sender_id: str | None = None) -> tuple[str, str]:
    if not isinstance(message, str) or not message.startswith(SMS_E2E_PREFIX):
        raise ValueError("not an Enclave encrypted SMS")
    if identity.ed25519_priv is None or identity.x25519_priv is None:
        raise RuntimeError("unlock your Enclave identity to receive encrypted SMS")
    raw = message[len(SMS_E2E_PREFIX):]
    if len(raw) > 4096:
        raise ValueError("encrypted SMS is too large")
    try:
        payload = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        raise ValueError("encrypted SMS envelope is malformed") from e
    if (not isinstance(payload, dict)
            or set(payload) != {"version", "from", "to", "timestamp", "token", "signature"}
            or type(payload.get("version")) is not int
            or payload.get("version") != MESSAGE_VERSION):
        raise ValueError("unsupported encrypted SMS envelope")

    sender_id = payload.get("from")
    recipient_id = payload.get("to")
    timestamp = payload.get("timestamp")
    token = payload.get("token")
    signature = payload.get("signature")
    if not all(isinstance(v, str) and v for v in (sender_id, recipient_id, timestamp, token, signature)):
        raise ValueError("encrypted SMS envelope is missing required fields")
    own_id = identity.get_user_id()
    if recipient_id != own_id:
        raise ValueError("encrypted SMS was addressed to a different Enclave identity")
    if expected_sender_id and sender_id != expected_sender_id:
        raise ValueError("encrypted SMS sender does not match the paired phone contact")

    ed_raw = _b64d(sender_id)
    sig_raw = _b64d(signature)
    if len(ed_raw) != 32 or len(sig_raw) != 64:
        raise ValueError("encrypted SMS has an invalid sender signature")
    if _b64e(ed_raw) != sender_id or _b64e(sig_raw) != signature:
        raise ValueError("encrypted SMS sender key or signature is not canonical")
    signed = {k: payload[k] for k in ("version", "from", "to", "timestamp", "token")}
    try:
        Ed25519PublicKey.from_public_bytes(ed_raw).verify(sig_raw, _canonical(signed))
    except (InvalidSignature, ValueError) as e:
        raise ValueError("encrypted SMS sender signature is invalid") from e

    # Bind the inner E2E ciphertext to this recipient and the signed timestamp.
    try:
        token_bytes = _b64d(token)
        inner = json.loads(token_bytes.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        header = inner.get("header", {})
    except Exception as e:
        raise ValueError("encrypted SMS contains an invalid E2E token") from e
    if (not isinstance(inner, dict) or not isinstance(header, dict)
            or header.get("chat_id") != own_id or header.get("created_at") != timestamp):
        raise ValueError("encrypted SMS E2E header does not match its signed envelope")

    try:
        plaintext = E2EManager(identity.x25519_priv).decrypt(token)
    except Exception as e:
        raise ValueError("encrypted SMS could not be decrypted with this identity") from e
    return plaintext, sender_id
