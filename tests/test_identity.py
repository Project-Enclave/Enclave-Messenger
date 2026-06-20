import os
import tempfile
import shutil

import pytest

from core.identity.key_manager import IdentityManager


def test_generate_save_load_delete(tmp_path):
    # Use a temporary storage dir to avoid touching user files
    store = tmp_path / "identity"
    im = IdentityManager(storage_dir=str(store))

    # Initially no identity
    assert im.has_identity() is False

    # Generate and save
    user_id = im.generate_new_identity()
    assert isinstance(user_id, str) and len(user_id) > 0

    # Save with passphrase
    assert im.save_identity(passphrase="testpass") is True
    assert im.has_identity() is True

    # Create new manager pointing to same dir and load
    im2 = IdentityManager(storage_dir=str(store))
    assert im2.has_identity() is True
    assert im2.load_identity(passphrase="testpass") is True
    assert im2.get_user_id() == user_id

    # Delete
    assert im2.delete_identity() is True
    assert im2.has_identity() is False


def test_load_with_wrong_passphrase(tmp_path):
    store = tmp_path / "identity"
    im = IdentityManager(storage_dir=str(store))
    im.generate_new_identity()
    im.save_identity(passphrase="right")

    im2 = IdentityManager(storage_dir=str(store))
    # Wrong passphrase should raise when loading (cryptography raises ValueError/TypeError)
    with pytest.raises(Exception):
        im2.load_identity(passphrase="wrong")
