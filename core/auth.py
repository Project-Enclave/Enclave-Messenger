"""
core/auth.py — Passphrase verification helper.

Provides a constant-time check against the stored identity so that
passphrase validation is centralised and cannot be accidentally skipped.
"""

import hmac


def verify_passphrase(identity_manager, passphrase: str) -> bool:
    """
    Return True if *passphrase* correctly decrypts the stored identity.

    Uses hmac.compare_digest on the derived key material so the check is
    constant-time and not trivially bypassable via timing side-channels.

    Raises RuntimeError if no identity is stored.
    """
    if not identity_manager.has_identity():
        raise RuntimeError("No identity found.")

    try:
        # Re-derive the key from the passphrase and compare against
        # the stored key material using constant-time comparison.
        candidate = identity_manager.derive_key(passphrase)
        stored    = identity_manager.derive_key_from_stored()
        return hmac.compare_digest(candidate, stored)
    except Exception:
        return False
