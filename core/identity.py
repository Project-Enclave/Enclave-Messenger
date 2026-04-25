# enclave/identity.py
# the identity system for enclave messenger
# handles key generation, storage, and contact trust
# ---------------------------------------------------
# dependencies: pip install cryptography

import json
import hashlib
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)


# ── helpers ────────────────────────────────────────────────────

def pubkey_to_bytes(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def fingerprint(pub_bytes: bytes) -> str:
    """human-readable fingerprint. shown in verification screens."""
    h = hashlib.sha256(pub_bytes).hexdigest().upper()
    return " ".join(h[i:i+4] for i in range(0, 20, 4))  # e.g. "A3F2 9C1D 88E0 B3D4 11F9"

def make_user_id(pub_bytes: bytes) -> str:
    """user id derived from identity pubkey. no central server needed."""
    return "enc1_" + hashlib.sha256(pub_bytes).hexdigest()[:32]


# ── layer 1: person identity ───────────────────────────────────

class PersonIdentity:
    """
    the root of who you are on enclave.
    one per person. lives on device. never leaves.
    """

    def __init__(self):
        # ed25519 for signing. this is your "real" identity.
        self._sign_key = Ed25519PrivateKey.generate()
        self.sign_pub  = pubkey_to_bytes(self._sign_key)

        self.user_id     = make_user_id(self.sign_pub)
        self.fingerprint = fingerprint(self.sign_pub)
        self.created_at  = datetime.now(timezone.utc).isoformat()

    def sign(self, data: bytes) -> bytes:
        return self._sign_key.sign(data)

    def export_public(self) -> dict:
        """safe to share with contacts"""
        return {
            "user_id":     self.user_id,
            "sign_pub":    self.sign_pub.hex(),
            "fingerprint": self.fingerprint,
            "created_at":  self.created_at,
        }


# ── layer 2: device bundle ─────────────────────────────────────

class DeviceBundle:
    """
    one per device (desktop, android, etc).
    handles actual key exchange and transport.
    signed by the person identity so contacts know it's really you.
    """

    NUM_ONE_TIME_PREKEYS = 50  # generate this many one-time prekeys at startup

    def __init__(self, identity: PersonIdentity, device_label: str = "main"):
        self.device_id    = os.urandom(8).hex()
        self.device_label = device_label

        # x25519 for key exchange (separate from signing key)
        self._signed_prekey    = X25519PrivateKey.generate()
        self.signed_prekey_pub = pubkey_to_bytes(self._signed_prekey)

        # identity signs the prekey so others can verify it belongs to you
        self.signed_prekey_sig = identity.sign(self.signed_prekey_pub)

        # one-time prekeys for async session startup (like signal)
        self._one_time_keys = [X25519PrivateKey.generate()
                               for _ in range(self.NUM_ONE_TIME_PREKEYS)]
        self.one_time_pubs  = [pubkey_to_bytes(k) for k in self._one_time_keys]

        # what transports this device supports
        self.capabilities = {
            "internet":  True,
            "lan":       True,
            "bluetooth": False,  # set to True when bt module is added
            "lora":      False,  # set to True when esp module is added
        }

    def pop_one_time_prekey(self):
        """
        remove and return one one-time prekey for a new session.
        one-time prekeys are used once then discarded (that's the whole point).
        caller should replenish when running low.
        """
        if not self._one_time_keys:
            return None, None
        priv = self._one_time_keys.pop(0)
        pub  = self.one_time_pubs.pop(0)
        return priv, pub

    def export_public(self, identity: PersonIdentity) -> dict:
        """the bundle you advertise over DHT or share locally"""
        return {
            "user_id":          identity.user_id,
            "device_id":        self.device_id,
            "device_label":     self.device_label,
            "sign_pub":         identity.sign_pub.hex(),
            "signed_prekey_pub": self.signed_prekey_pub.hex(),
            "signed_prekey_sig": self.signed_prekey_sig.hex(),
            "one_time_pubs":    [p.hex() for p in self.one_time_pubs],
            "capabilities":     self.capabilities,
        }


# ── layer 3: contact trust ─────────────────────────────────────

TRUST_UNVERIFIED = "unverified"   # seen for the first time, TOFU
TRUST_VERIFIED   = "verified"     # fingerprints matched out-of-band
TRUST_BLOCKED    = "blocked"

class Contact:
    """
    a contact you know about. stores their public identity.
    trust starts at TOFU (unverified) and upgrades when you verify.
    """

    def __init__(self, bundle: dict):
        self.user_id          = bundle["user_id"]
        self.sign_pub         = bytes.fromhex(bundle["sign_pub"])
        self.signed_prekey_pub = bytes.fromhex(bundle["signed_prekey_pub"])
        self.signed_prekey_sig = bytes.fromhex(bundle["signed_prekey_sig"])
        self.one_time_pubs    = [bytes.fromhex(p) for p in bundle.get("one_time_pubs", [])]
        self.capabilities     = bundle.get("capabilities", {})
        self.trust            = TRUST_UNVERIFIED
        self.fingerprint      = fingerprint(self.sign_pub)
        self.first_seen       = datetime.now(timezone.utc).isoformat()
        self.display_name     = bundle.get("device_label", "unknown")

    def verify_prekey(self) -> bool:
        """
        check that the signed prekey was actually signed by their identity key.
        always do this before using someone's prekey.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.exceptions import InvalidSignature

        try:
            pub = Ed25519PublicKey.from_public_bytes(self.sign_pub)
            pub.verify(self.signed_prekey_sig, self.signed_prekey_pub)
            return True
        except InvalidSignature:
            return False

    def mark_verified(self):
        """call this after user confirms fingerprint out-of-band"""
        self.trust = TRUST_VERIFIED

    def pop_one_time_prekey(self):
        """consume one one-time prekey from their bundle"""
        if self.one_time_pubs:
            return self.one_time_pubs.pop(0)
        return None  # None = no one-time prekey available, still works, just slightly weaker

    def export(self) -> dict:
        return {
            "user_id":          self.user_id,
            "display_name":     self.display_name,
            "fingerprint":      self.fingerprint,
            "trust":            self.trust,
            "first_seen":       self.first_seen,
            "capabilities":     self.capabilities,
        }


# ── contact book ───────────────────────────────────────────────

class ContactBook:
    """simple in-memory contact store. swap out for sqlite later."""

    def __init__(self):
        self._contacts: dict[str, Contact] = {}

    def add_contact(self, bundle: dict) -> Contact:
        uid = bundle["user_id"]
        if uid in self._contacts:
            existing = self._contacts[uid]
            # key changed? that's suspicious. warn before accepting.
            if existing.sign_pub != bytes.fromhex(bundle["sign_pub"]):
                raise KeyMismatchError(
                    f"identity key changed for {uid}. "
                    "verify this is really them before accepting."
                )
            return existing
        contact = Contact(bundle)
        self._contacts[uid] = contact
        return contact

    def get(self, user_id: str) -> Contact | None:
        return self._contacts.get(user_id)

    def all_contacts(self) -> list[dict]:
        return [c.export() for c in self._contacts.values()]


class KeyMismatchError(Exception):
    """raised when a contact's identity key changes unexpectedly"""
    pass


# ── quick demo ─────────────────────────────────────────────────

if __name__ == "__main__":
    print("── generating alice's identity ──")
    alice_identity = PersonIdentity()
    alice_device   = DeviceBundle(alice_identity, "alice-desktop")

    print(f"user id:     {alice_identity.user_id}")
    print(f"fingerprint: {alice_identity.fingerprint}")
    print(f"device id:   {alice_device.device_id}")
    print(f"prekeys:     {len(alice_device.one_time_pubs)} one-time prekeys ready")

    print()
    print("── alice exports her public bundle ──")
    bundle = alice_device.export_public(alice_identity)
    print(json.dumps({k: v for k, v in bundle.items() if k != "one_time_pubs"}, indent=2))

    print()
    print("── bob discovers alice and adds her as a contact ──")
    book = ContactBook()
    alice_contact = book.add_contact(bundle)
    prekey_valid  = alice_contact.verify_prekey()
    print(f"prekey signature valid: {prekey_valid}")
    print(f"trust level: {alice_contact.trust}")

    print()
    print("── bob verifies alice's fingerprint out-of-band ──")
    alice_contact.mark_verified()
    print(f"trust level now: {alice_contact.trust}")
    print(f"fingerprint to confirm: {alice_contact.fingerprint}")

