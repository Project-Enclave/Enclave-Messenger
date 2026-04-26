"""
setup.py — Enclave Messenger first-run setup.

Does:
  1. Checks Python version (3.10+)
  2. Installs dependencies (pip first, falls back to uv venv)
  3. Walks through config (username, SMS gateway creds)
  4. Creates the identity if none exists
  5. Deletes itself on success

Run with: python3 setup.py
"""

import sys
import os
import subprocess
import shutil

VENV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")


# ── helpers ─────────────────────────────────────────────────────────────────

def banner(text):
    print(f"\n\033[96m{'=' * 50}\033[0m")
    print(f"\033[96m  {text}\033[0m")
    print(f"\033[96m{'=' * 50}\033[0m")

def ok(text):  print(f"  \033[92m✓\033[0m  {text}")
def err(text): print(f"  \033[91m✗\033[0m  {text}")
def info(text): print(f"  \033[93m→\033[0m  {text}")

def ask(prompt, default=None, secret=False):
    display = f"{prompt} [{default}]: " if default else f"{prompt}: "
    if secret:
        import getpass
        val = getpass.getpass(display).strip()
    else:
        val = input(display).strip()
    return val if val else default


def run(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


def venv_python():
    """Return the Python executable inside .venv."""
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def venv_active():
    """True if we're already running inside .venv."""
    return sys.prefix == VENV_DIR or os.path.abspath(sys.executable).startswith(
        os.path.abspath(VENV_DIR)
    )


# ── steps ─────────────────────────────────────────────────────────────────

def step_python_version():
    banner("Step 1 — Python version check")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 10):
        err(f"Python 3.10+ required. You have {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor} — OK")


def step_install_requirements():
    banner("Step 2 — Installing requirements")
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(req_file):
        err("requirements.txt not found!")
        sys.exit(1)

    # ─ try pip first ────────────────────────────────────────────────────
    pip_check = run([sys.executable, "-m", "pip", "--version"], capture_output=True)
    if pip_check.returncode == 0:
        result = run([sys.executable, "-m", "pip", "install", "-r", req_file])
        if result.returncode == 0:
            ok("All requirements installed via pip.")
            return
        err("pip install failed.")
        sys.exit(1)

    # ─ pip not available: fall back to uv ──────────────────────────────
    info("pip not found — falling back to uv")

    uv = shutil.which("uv")
    if not uv:
        err("uv not found either. Install uv first: https://github.com/astral-sh/uv")
        err("  curl -Ls https://astral.sh/uv/install.sh | sh")
        sys.exit(1)

    # create venv if not already inside one
    if not venv_active():
        if not os.path.exists(VENV_DIR):
            info(f"Creating venv at {VENV_DIR} ...")
            result = run([uv, "venv", VENV_DIR])
            if result.returncode != 0:
                err("uv venv creation failed.")
                sys.exit(1)
            ok(f"Venv created at {VENV_DIR}")
        else:
            ok(f"Venv already exists at {VENV_DIR}")

        # re-launch setup.py inside the venv
        info("Re-launching setup inside venv...")
        py = venv_python()
        result = run([py, os.path.abspath(__file__)])
        sys.exit(result.returncode)

    # we are inside venv — install with uv pip
    info("Installing requirements with uv pip ...")
    result = run([uv, "pip", "install", "-r", req_file])
    if result.returncode != 0:
        err("uv pip install failed.")
        sys.exit(1)
    ok("All requirements installed via uv.")
    ok(f"Activate venv with: source {VENV_DIR}/bin/activate")


def step_config():
    banner("Step 3 — App configuration")
    from core.storage import ConfigStore
    config = ConfigStore()

    current_user = config.username or ""
    username = ask("Your display name", default=current_user or None)
    if username:
        config.username = username
        ok(f"Username set to: {username}")
    else:
        ok("Username skipped.")

    print("\n  SMS Gateway (android-sms-gateway) — optional, press Enter to skip")
    sms_user = ask("  Gateway username", default=None)
    if sms_user:
        sms_pass = ask("  Gateway password", secret=True)
        sms_host = ask("  Device local IP (leave blank for cloud mode)", default=None)
        config.set_sms_gateway(
            provider=sms_user,
            api_key=sms_pass,
            sender_id=sms_host or "cloud",
        )
        ok("SMS gateway config saved.")
    else:
        ok("SMS gateway skipped.")

    port_str = ask("  Web UI port", default="5000")
    try:
        config.set_setting("port", int(port_str))
        ok(f"Port set to: {port_str}")
    except (ValueError, TypeError):
        ok("Invalid port, keeping default 5000.")


def step_identity():
    banner("Step 4 — Identity")
    from core.identity import IdentityManager
    ident = IdentityManager()
    if ident.has_identity():
        ok("Identity already exists — skipping.")
        return
    print("  No identity found. Creating one now...")
    import getpass
    passphrase = getpass.getpass("  Choose a passphrase: ").strip()
    if not passphrase:
        err("Passphrase cannot be empty.")
        sys.exit(1)
    confirm = getpass.getpass("  Confirm passphrase: ").strip()
    if passphrase != confirm:
        err("Passphrases do not match.")
        sys.exit(1)
    ident.generate_new_identity()
    ident.save_identity(passphrase=passphrase)
    ok(f"Identity created. User ID: {ident.get_user_id()}")


def step_self_destruct():
    banner("Step 5 — Cleanup")
    try:
        os.remove(os.path.abspath(__file__))
        ok("setup.py deleted — setup complete!")
    except OSError as e:
        err(f"Could not delete setup.py: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n\033[95m  Enclave Messenger — Setup\033[0m")
    step_python_version()
    step_install_requirements()
    step_config()
    step_identity()
    step_self_destruct()
    print("\n\033[92m  All done! Run with: python web.py\033[0m\n")
