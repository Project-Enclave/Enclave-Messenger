"""
setup_wizard.py — the interactive first-run steps (display name, SMS gateway,
web port, identity), shared by `pe-em setup` and the developer script set.py.

Unlike the old set.py steps this writes to the ACTIVE PROFILE's config (the old
code built a bare ConfigStore() which wrote to ./storage/ in whatever directory
you happened to run it from), never installs packages and never deletes itself.
"""
from __future__ import annotations

import getpass
import sys


def _ask(prompt, default=None, secret=False):
    shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
    val = (getpass.getpass(shown) if secret else input(shown)).strip()
    return val if val else default


def configure(config) -> None:
    """Display name, optional SMS gateway, web port -> saved into `config`."""
    current = config.username or ""
    name = _ask("Your display name", default=current or None)
    if name:
        config.username = name
        print("  username set.")

    print("\n  SMS Gateway (android-sms-gateway) - optional, press Enter to skip")
    user = _ask("  Gateway username")
    if user:
        pw = _ask("  Gateway password", secret=True)
        host = _ask("  Device local IP (blank for cloud mode)")
        config.set_sms_gateway(provider=user, api_key=pw, sender_id=host or "cloud")
        print("  SMS gateway config saved.")

    port = _ask("  Web UI port", default="5000")
    try:
        config.set_setting("port", int(port))
        print(f"  port set to {port}")
    except (TypeError, ValueError):
        print("  invalid port, keeping the default (5000)")


def create_identity(identity) -> bool:
    """Create + save an identity unless one exists. Returns True when one exists afterwards."""
    if identity.has_identity():
        print("  identity already exists - skipping.")
        return True
    print("  No identity found. Creating one now...")
    print("  There is no password reset: if you forget this passphrase, the identity is gone.")
    pw = getpass.getpass("  Choose a passphrase: ").strip()
    if not pw:
        print("  passphrase cannot be empty.", file=sys.stderr)
        return False
    if pw != getpass.getpass("  Confirm passphrase: ").strip():
        print("  passphrases do not match.", file=sys.stderr)
        return False
    identity.generate_new_identity()
    identity.save_identity(passphrase=pw)
    print(f"  identity created. User ID: {identity.get_user_id()}")
    return True


def main(argv=None) -> int:
    import argparse
    argparse.ArgumentParser(
        prog="pe-em setup",
        description="Interactive first-run wizard for the active profile: display name, "
                    "optional SMS gateway, web port and identity. Installs nothing and never "
                    "deletes anything.").parse_args(argv)
    if not sys.stdin.isatty():
        print("pe-em setup is interactive; run it in a terminal.", file=sys.stderr)
        return 1
    from enclave_messenger import main as core
    print("\nEnclave Messenger setup (profile: %s)\n" % core._active_profile)
    configure(core.config)
    print()
    if not create_identity(core.identity):
        return 1
    print("\nAll done. Start the app with:  pe-em   (or `pe-em tui`)")
    return 0
