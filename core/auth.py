"""
core/auth.py — Passphrase verification helper.

Provides a constant-time check against the stored identity so that
passphrase validation is centralised and cannot be accidentally skipped.
"""


def verify_passphrase(identity_manager, passphrase: str) -> bool:
    """
    Return True if *passphrase* correctly decrypts the stored identity.

    Attempts to load the PEM-encrypted keypair with the given passphrase.
    If decryption succeeds, the passphrase is valid.

    Raises RuntimeError if no identity is stored.
    """
    if not identity_manager.has_identity():
        raise RuntimeError("No identity found.")

    try:
        identity_manager.load_identity(passphrase)
        return True
    except Exception:
        return False
