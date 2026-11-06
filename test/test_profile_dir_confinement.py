"""A profile's data_dir from the registry must stay inside the data directory
(or the legacy ~/.enclave-messenger directory for old absolute entries)."""
import os
import tempfile

import pytest


@pytest.fixture()
def profiles(monkeypatch):
    home = tempfile.mkdtemp()
    monkeypatch.setenv("ENCLAVE_HOME", home)
    from enclave_messenger import paths
    from enclave_messenger.core import profiles as p
    paths.reset_cache()
    yield p, paths
    paths.reset_cache()


def test_relative_inside_is_allowed(profiles):
    p, paths = profiles
    got = p._resolve_dir("profiles/alice")
    assert got == os.path.join(os.path.realpath(paths.data_dir()), "profiles", "alice")


def test_absolute_inside_is_allowed(profiles):
    p, paths = profiles
    inside = os.path.join(os.path.realpath(paths.data_dir()), "profiles", "old")
    assert p._resolve_dir(inside) == inside


@pytest.mark.parametrize("bad", ["../escape", "profiles/../../escape", "/etc", "/tmp/evil"])
def test_outside_is_refused(profiles, bad):
    p, _ = profiles
    with pytest.raises(ValueError):
        p._resolve_dir(bad)


def test_data_dir_itself_is_refused(profiles):
    p, _ = profiles
    with pytest.raises(ValueError):
        p._resolve_dir(".")
