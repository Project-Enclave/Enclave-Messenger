"""
reset.py — Enclave Messenger full reset.

Undoes everything setup.py did:
  1. Deletes ~/.enclave-messenger entirely (all profiles + identity)
  2. Wipes config           (storage/config/config.json)
  3. Wipes chat/key/log     (storage/ subdirs)
  4. Removes .venv          (if created by setup.py uv fallback)
  5. Restores setup.py      (so you can run setup again)

Run with: `python3 reset.py`
"""

import os
import sys
import shutil

# ── colours ──────────────────────────────────────────────────────────────────

def banner(text):
    print(f"\n\033[96m{'=' * 50}\033[0m")
    print(f"\033[96m  {text}\033[0m")
    print(f"\033[96m{'=' * 50}\033[0m")

def ok(text):   print(f"  \033[92m✓\033[0m  {text}")
def err(text):  print(f"  \033[91m✗\033[0m  {text}")
def info(text): print(f"  \033[93m→\033[0m  {text}")
def skip(text): print(f"  \033[90m–\033[0m  {text} (not found, skipping)")


# ── helpers ───────────────────────────────────────────────────────────────────

HERE = os.path.dirname(os.path.abspath(__file__))

def remove_file(path, label):
    if os.path.exists(path):
        try:
            os.remove(path)
            ok(f"Deleted {label}: {path}")
        except OSError as e:
            err(f"Could not delete {label}: {e}")
    else:
        skip(label)

def remove_dir(path, label):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
            ok(f"Deleted {label}: {path}")
        except OSError as e:
            err(f"Could not delete {label}: {e}")
    else:
        skip(label)


# ── steps ─────────────────────────────────────────────────────────────────────

def step_identity():
    banner("Step 1 — Delete identity & all profiles")
    enclave_dir = os.path.expanduser("~/.enclave-messenger")
    remove_dir(enclave_dir, "~/.enclave-messenger")


def step_config():
    banner("Step 2 — Wipe config")
    config_file = os.path.join(HERE, "storage", "config", "config.json")
    remove_file(config_file, "config.json")


def step_storage():
    banner("Step 3 — Wipe storage data")
    for sub in ("chats", "keys", "logs"):
        remove_dir(os.path.join(HERE, "storage", sub), f"storage/{sub}")
    # remove storage/config dir if now empty
    config_dir = os.path.join(HERE, "storage", "config")
    if os.path.isdir(config_dir) and not os.listdir(config_dir):
        remove_dir(config_dir, "storage/config")
    # remove storage dir if now empty
    storage_dir = os.path.join(HERE, "storage")
    if os.path.isdir(storage_dir) and not os.listdir(storage_dir):
        remove_dir(storage_dir, "storage/")


def step_venv():
    banner("Step 4 — Remove .venv")
    venv_dir = os.path.join(HERE, ".venv")
    remove_dir(venv_dir, ".venv")


def step_restore_setup():
    banner("Step 5 — Restore setup.py")
    setup_path = os.path.join(HERE, "set.py")
    if os.path.exists(setup_path):
        skip("set.py already exists")
        return

    info("set.py was deleted by the self-destruct — restoring from git...")
    # try git checkout first
    try:
        import subprocess
        result = subprocess.run(
            ["git", "checkout", "HEAD", "--", "set.py"],
            cwd=HERE,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            ok("set.py restored via git checkout.")
            return
        else:
            info(f"git checkout failed: {result.stderr.strip()}")
    except FileNotFoundError:
        info("git not available.")

    # fallback: download from GitHub
    info("Trying to download set.py from GitHub...")
    try:
        import urllib.request
        url = (
            "https://raw.githubusercontent.com/"
            "Project-Enclave/Enclave-Messenger/main/set.py"
        )
        urllib.request.urlretrieve(url, setup_path)
        ok("set.py downloaded from GitHub.")
    except Exception as e:
        err(f"Could not restore set.py automatically: {e}")
        err("Download it manually from: https://github.com/Project-Enclave/Enclave-Messenger/blob/main/set.py")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n\033[95m  Enclave Messenger — Reset\033[0m")
    print("\n  This will delete your identity, all profiles, config, and all local data.")
    print("  This cannot be undone.")

    confirm = input("\n  Type 'yes' to continue: ").strip().lower()
    if confirm != "yes":
        print("\n  Aborted. Nothing was changed.\n")
        sys.exit(0)

    step_identity()
    step_config()
    step_storage()
    step_venv()
    step_restore_setup()

    print("\n\033[92m  Reset complete. Run python3 set.py to start fresh.\033[0m\n")


if __name__ == "__main__":
    main()
